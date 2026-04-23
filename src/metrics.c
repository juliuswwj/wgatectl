#include "metrics.h"
#include "json.h"
#include "log.h"
#include "util.h"

#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* Per (client_ip, domain) bucket. Flat open-addressed table. */

#define BUCKET_CAP  4096

typedef struct {
    uint32_t  client_ip;     /* 0 = empty */
    char      domain[96];
    uint64_t  bytes;
    uint32_t  pkts;
} bucket_t;

struct wg_metrics {
    bucket_t           buckets[BUCKET_CAP];

    /* for CPU% delta */
    unsigned long long prev_idle;
    unsigned long long prev_total;
    bool               have_prev_cpu;
};

static uint32_t hash_domain(uint32_t client, const char *domain) {
    uint32_t h = 2166136261u ^ client;
    for (const char *p = domain; *p; p++) {
        h ^= (uint8_t)*p;
        h *= 16777619u;
    }
    return h;
}

wg_metrics_t *metrics_new(void) {
    wg_metrics_t *m = calloc(1, sizeof(*m));
    return m;
}

void metrics_free(wg_metrics_t *m) { free(m); }

static bucket_t *find_bucket(wg_metrics_t *m, uint32_t client,
                             const char *domain, bool create) {
    uint32_t idx = hash_domain(client, domain) & (BUCKET_CAP - 1);
    for (int i = 0; i < 32; i++) {
        bucket_t *b = &m->buckets[(idx + i) & (BUCKET_CAP - 1)];
        if (b->client_ip == 0) {
            if (!create) return NULL;
            b->client_ip = client;
            strncpy(b->domain, domain, sizeof(b->domain) - 1);
            b->domain[sizeof(b->domain) - 1] = 0;
            b->bytes = 0;
            b->pkts  = 0;
            return b;
        }
        if (b->client_ip == client && strcmp(b->domain, domain) == 0)
            return b;
    }
    /* saturation: overwrite idx slot */
    bucket_t *b = &m->buckets[idx];
    b->client_ip = client;
    strncpy(b->domain, domain, sizeof(b->domain) - 1);
    b->domain[sizeof(b->domain) - 1] = 0;
    b->bytes = 0;
    b->pkts  = 0;
    return b;
}

void metrics_observe_flow(wg_metrics_t *m,
                          uint32_t client_ip, uint32_t server_ip,
                          const char *domain, uint32_t wire_len) {
    if (!m || client_ip == 0) return;
    char ipbuf[16];
    const char *key;
    if (domain && *domain) {
        key = domain;
    } else {
        ip_format(server_ip, ipbuf);
        key = ipbuf;
    }
    bucket_t *b = find_bucket(m, client_ip, key, true);
    if (!b) return;
    b->bytes += wire_len;
    b->pkts  += 1;
}

void metrics_observe_dns_query(wg_metrics_t *m, uint32_t client_ip,
                               const char *qname) {
    (void)m; (void)client_ip; (void)qname;
}

/* ----------------------- emit traffic JSONL ----------------------- */

static int cmp_bucket_by_bytes_desc(const void *a, const void *b) {
    const bucket_t *x = a, *y = b;
    if (x->bytes < y->bytes) return 1;
    if (x->bytes > y->bytes) return -1;
    return 0;
}

static void emit_traffic_event(jsonl_t *jl, int64_t ts, uint32_t client_ip,
                               const wg_leases_t *leases,
                               const wg_blocks_t *blocks,
                               bucket_t *buckets_of_client, size_t nb) {
    char iso[48];
    ts_iso8601(ts, iso, sizeof(iso));
    char ipbuf[16];
    ip_format(client_ip, ipbuf);
    const wg_lease_t *l = leases_by_ip(leases, client_ip);

    json_out_t j;
    json_out_init(&j);
    json_obj_begin(&j);
    json_kstr(&j, "ts",   iso);
    json_kstr(&j, "kind", "traffic");
    json_kstr(&j, "ip",   ipbuf);
    if (l && l->name[0]) json_kstr(&j, "name", l->name);
    else                 json_knull(&j, "name");
    if (l) {
        char macbuf[18];
        mac_format(l->mac, macbuf);
        json_kstr(&j, "mac", macbuf);
    }
    json_kbool(&j, "blocked", blocks_contains_ip(blocks, leases, client_ip));

    qsort(buckets_of_client, nb, sizeof(*buckets_of_client),
          cmp_bucket_by_bytes_desc);

    json_key(&j, "domains");
    json_arr_begin(&j);
    size_t top = nb < 64 ? nb : 64;
    for (size_t i = 0; i < top; i++) {
        json_obj_begin(&j);
        json_kstr(&j, "name",  buckets_of_client[i].domain);
        json_ku64(&j, "bytes", buckets_of_client[i].bytes);
        json_ku64(&j, "pkts",  buckets_of_client[i].pkts);
        json_obj_end(&j);
    }
    if (nb > top) {
        uint64_t obytes = 0, opkts = 0;
        for (size_t i = top; i < nb; i++) {
            obytes += buckets_of_client[i].bytes;
            opkts  += buckets_of_client[i].pkts;
        }
        json_obj_begin(&j);
        json_kstr(&j, "name",  "...other");
        json_ku64(&j, "bytes", obytes);
        json_ku64(&j, "pkts",  opkts);
        json_obj_end(&j);
    }
    json_arr_end(&j);
    json_obj_end(&j);
    if (jl && j.buf) jsonl_append(jl, j.buf, j.len);
    json_out_free(&j);
}

/* --------------------------- system event --------------------------- */

static void read_cpu(unsigned long long *out_idle, unsigned long long *out_total) {
    *out_idle  = 0;
    *out_total = 0;
    FILE *f = fopen("/proc/stat", "r");
    if (!f) return;
    char line[256];
    if (fgets(line, sizeof(line), f)) {
        unsigned long long a[8] = { 0 };
        int n = sscanf(line, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
                       &a[0], &a[1], &a[2], &a[3], &a[4], &a[5], &a[6], &a[7]);
        if (n >= 4) {
            unsigned long long idle = a[3] + a[4];
            unsigned long long total = 0;
            for (int i = 0; i < n && i < 8; i++) total += a[i];
            *out_idle  = idle;
            *out_total = total;
        }
    }
    fclose(f);
}

static void emit_system_event(jsonl_t *jl, int64_t ts, wg_metrics_t *m) {
    char iso[48];
    ts_iso8601(ts, iso, sizeof(iso));

    json_out_t j;
    json_out_init(&j);
    json_obj_begin(&j);
    json_kstr(&j, "ts", iso);
    json_kstr(&j, "kind", "system");

    /* CPU %  */
    unsigned long long idle, total;
    read_cpu(&idle, &total);
    double cpu_pct = 0.0;
    if (m->have_prev_cpu && total > m->prev_total) {
        unsigned long long d_total = total - m->prev_total;
        unsigned long long d_idle  = idle  - m->prev_idle;
        if (d_total > 0) cpu_pct = 100.0 * (double)(d_total - d_idle) / (double)d_total;
    }
    m->prev_idle     = idle;
    m->prev_total    = total;
    m->have_prev_cpu = true;
    json_kf64(&j, "cpu_pct", cpu_pct, 2);

    /* loadavg */
    {
        double la[3] = { 0 };
        FILE *f = fopen("/proc/loadavg", "r");
        if (f) { (void)fscanf(f, "%lf %lf %lf", &la[0], &la[1], &la[2]); fclose(f); }
        json_key(&j, "load");
        json_arr_begin(&j);
        json_f64(&j, la[0], 2);
        json_f64(&j, la[1], 2);
        json_f64(&j, la[2], 2);
        json_arr_end(&j);
    }

    /* meminfo */
    {
        unsigned long memtotal_kb = 0, memfree_kb = 0, buffers_kb = 0,
                      cached_kb   = 0, sreclaim_kb = 0, memavail_kb = 0;
        FILE *f = fopen("/proc/meminfo", "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                unsigned long v;
                if      (sscanf(line, "MemTotal: %lu kB", &v) == 1)     memtotal_kb = v;
                else if (sscanf(line, "MemFree: %lu kB", &v) == 1)      memfree_kb = v;
                else if (sscanf(line, "MemAvailable: %lu kB", &v) == 1) memavail_kb = v;
                else if (sscanf(line, "Buffers: %lu kB", &v) == 1)      buffers_kb = v;
                else if (sscanf(line, "Cached: %lu kB", &v) == 1)       cached_kb = v;
                else if (sscanf(line, "SReclaimable: %lu kB", &v) == 1) sreclaim_kb = v;
            }
            fclose(f);
        }
        unsigned long long avail = memavail_kb ? (unsigned long long)memavail_kb
                                               : (unsigned long long)(memfree_kb + buffers_kb + cached_kb + sreclaim_kb);
        unsigned long long used_b  = (unsigned long long)(memtotal_kb - (avail < memtotal_kb ? avail : 0)) * 1024ull;
        unsigned long long total_b = (unsigned long long)memtotal_kb * 1024ull;
        json_key(&j, "mem");
        json_obj_begin(&j);
        json_ku64(&j, "used",  used_b);
        json_ku64(&j, "total", total_b);
        json_obj_end(&j);
    }

    /* disk */
    {
        const char *mounts[] = { "/", "/mnt/ssd", NULL };
        json_key(&j, "disk");
        json_arr_begin(&j);
        for (int i = 0; mounts[i]; i++) {
            struct statvfs st;
            if (statvfs(mounts[i], &st) != 0) continue;
            unsigned long long frsize = st.f_frsize ? st.f_frsize : st.f_bsize;
            unsigned long long total_b = (unsigned long long)st.f_blocks * frsize;
            unsigned long long avail_b = (unsigned long long)st.f_bavail * frsize;
            unsigned long long used_b  = total_b > avail_b ? (total_b - avail_b) : 0;
            json_obj_begin(&j);
            json_kstr(&j, "mount", mounts[i]);
            json_ku64(&j, "used",  used_b);
            json_ku64(&j, "total", total_b);
            json_obj_end(&j);
        }
        json_arr_end(&j);
    }

    /* temperature */
    {
        json_key(&j, "temp_c");
        json_arr_begin(&j);
        DIR *d = opendir("/sys/class/thermal");
        if (d) {
            struct dirent *de;
            while ((de = readdir(d)) != NULL) {
                if (strncmp(de->d_name, "thermal_zone", 12) != 0) continue;
                char tpath[512], zpath[512];
                snprintf(tpath, sizeof(tpath), "/sys/class/thermal/%s/temp", de->d_name);
                snprintf(zpath, sizeof(zpath), "/sys/class/thermal/%s/type", de->d_name);
                size_t tn = 0, zn = 0;
                char *tbuf = read_small_file(tpath, 64, &tn);
                char *zbuf = read_small_file(zpath, 64, &zn);
                if (tbuf) {
                    long mC = strtol(tbuf, NULL, 10);
                    char zone[48] = "?";
                    if (zbuf) {
                        size_t k = 0;
                        while (k < sizeof(zone) - 1 && zbuf[k] && zbuf[k] != '\n') {
                            zone[k] = zbuf[k];
                            k++;
                        }
                        zone[k] = 0;
                    }
                    double cc = (double)mC / 1000.0;
                    if (cc >= -40.0 && cc <= 200.0) {
                        json_obj_begin(&j);
                        json_kstr(&j, "zone", zone);
                        json_kf64(&j, "c", cc, 1);
                        json_obj_end(&j);
                    }
                }
                free(tbuf); free(zbuf);
            }
            closedir(d);
        }
        json_arr_end(&j);
    }

    /* uptime */
    {
        struct timespec ts_b;
        clock_gettime(CLOCK_BOOTTIME, &ts_b);
        json_ki64(&j, "uptime_s", (int64_t)ts_b.tv_sec);
    }

    /* /proc/net/dev */
    {
        json_key(&j, "iface");
        json_arr_begin(&j);
        FILE *f = fopen("/proc/net/dev", "r");
        if (f) {
            char line[512];
            int n = 0;
            while (fgets(line, sizeof(line), f)) {
                if (n++ < 2) continue;  /* header */
                char *colon = strchr(line, ':');
                if (!colon) continue;
                *colon = 0;
                char name[32];
                const char *start = line;
                while (*start && isspace((unsigned char)*start)) start++;
                strncpy(name, start, sizeof(name) - 1);
                name[sizeof(name) - 1] = 0;
                if (!*name || strcmp(name, "lo") == 0) continue;
                unsigned long long rx_b = 0, tx_b = 0;
                unsigned long long dummy;
                int c = sscanf(colon + 1,
                       "%llu %llu %llu %llu %llu %llu %llu %llu"
                       " %llu",
                       &rx_b, &dummy, &dummy, &dummy, &dummy, &dummy, &dummy, &dummy,
                       &tx_b);
                if (c < 9) continue;
                json_obj_begin(&j);
                json_kstr(&j, "name", name);
                json_ku64(&j, "rx",   rx_b);
                json_ku64(&j, "tx",   tx_b);
                json_obj_end(&j);
            }
            fclose(f);
        }
        json_arr_end(&j);
    }

    json_obj_end(&j);
    if (jl && j.buf) jsonl_append(jl, j.buf, j.len);
    json_out_free(&j);
}

/* ------------------------- control event ------------------------- */

void metrics_emit_control(jsonl_t *jl, int64_t ts_secs,
                          const char *name, const char *ip_str,
                          const char *action, const char *reason) {
    char iso[48];
    ts_iso8601(ts_secs, iso, sizeof(iso));
    json_out_t j;
    json_out_init(&j);
    json_obj_begin(&j);
    json_kstr(&j, "ts",     iso);
    json_kstr(&j, "kind",   "control");
    json_kstr(&j, "action", action);
    if (name   && *name)   json_kstr(&j, "name", name);
    if (ip_str && *ip_str) json_kstr(&j, "ip",   ip_str);
    if (reason && *reason) json_kstr(&j, "reason", reason);
    json_obj_end(&j);
    if (jl && j.buf) jsonl_append(jl, j.buf, j.len);
    json_out_free(&j);
}

/* --------------------------- iterator ------------------------------- */

void metrics_foreach_bucket(const wg_metrics_t *m,
                            metrics_bucket_cb_t cb, void *arg) {
    if (!m || !cb) return;
    for (size_t i = 0; i < BUCKET_CAP; i++) {
        const bucket_t *b = &m->buckets[i];
        if (b->client_ip == 0) continue;
        cb(b->client_ip, b->domain, b->bytes, b->pkts, arg);
    }
}

/* ---------------------------- flush --------------------------------- */

void metrics_flush(wg_metrics_t *m,
                   jsonl_t *jl,
                   const wg_leases_t *leases,
                   const wg_blocks_t *blocks,
                   int64_t ts_secs) {
    if (!m) return;

    /* gather list of active clients */
    uint32_t seen_clients[256]; size_t seen_n = 0;
    size_t   n_buckets_per_client[256];
    for (size_t i = 0; i < BUCKET_CAP; i++) {
        if (m->buckets[i].client_ip == 0) continue;
        uint32_t c = m->buckets[i].client_ip;
        int idx = -1;
        for (size_t k = 0; k < seen_n; k++)
            if (seen_clients[k] == c) { idx = (int)k; break; }
        if (idx < 0) {
            if (seen_n >= 256) continue;
            idx = (int)seen_n++;
            seen_clients[idx] = c;
            n_buckets_per_client[idx] = 0;
        }
        n_buckets_per_client[idx]++;
    }

    /* emit one traffic event per client */
    for (size_t i = 0; i < seen_n; i++) {
        uint32_t c = seen_clients[i];
        bucket_t *pack = malloc(n_buckets_per_client[i] * sizeof(*pack));
        if (!pack) continue;
        size_t nb = 0;
        for (size_t k = 0; k < BUCKET_CAP; k++) {
            if (m->buckets[k].client_ip == c) pack[nb++] = m->buckets[k];
        }
        emit_traffic_event(jl, ts_secs, c, leases, blocks, pack, nb);
        free(pack);
    }

    emit_system_event(jl, ts_secs, m);

    /* reset aggregator */
    memset(m->buckets, 0, sizeof(m->buckets));
}
