#include "filterd.h"
#include "log.h"
#include "util.h"

#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define FILTERD_TARGETS_MAX  256
#define FILTERD_PENDING_CAP  256
#define FILTERD_TIMEOUT_S    600    /* matches sniffer reverse-map TTL */

struct wg_filterd {
    char      **targets;          /* lower-cased domain suffixes */
    size_t      n_targets, cap_targets;

    /* In-memory queue of observed IPs awaiting batch ipset add. The
     * sniffer pushes; the per-minute flush drains. Single-threaded
     * (epoll loop), so no lock needed. */
    uint32_t    pending[FILTERD_PENDING_CAP];
    size_t      pending_n;

    char        path       [256];   /* filterd.json */
    char        legacy_path[256];   /* legacy supervised.json (one-shot) */
    char        ipset_bin  [96];

    bool        dirty;
    bool        legacy_consumed;
};

/* ---------------------------- small utils ------------------------- */

static char *dup_lower(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s);
    char *o = malloc(n + 1);
    if (!o) return NULL;
    for (size_t i = 0; i < n; i++) o[i] = (char)tolower((unsigned char)s[i]);
    o[n] = 0;
    return o;
}

static bool label_suffix_match(const char *domain, const char *suffix) {
    size_t dn = strlen(domain), sn = strlen(suffix);
    if (sn == 0 || dn < sn) return false;
    size_t off = dn - sn;
    if (strcmp(domain + off, suffix) != 0) return false;
    if (off == 0) return true;
    return domain[off - 1] == '.';
}

/* ------------------------------ ipset ----------------------------- */

static int run_ipset_argv(const char *bin, char *const argv[]) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, 1); if (devnull > 2) close(devnull); }
        execv(bin, argv);
        _exit(127);
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) { /* retry on EINTR */ }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
}

static void ipset_add_filterd(wg_filterd_t *f, uint32_t ip) {
    if (!f->ipset_bin[0] || ip == 0) return;
    char ipbuf[16];
    ip_format(ip, ipbuf);
    char timeout_s[16];
    snprintf(timeout_s, sizeof(timeout_s), "%d", FILTERD_TIMEOUT_S);
    char *argv[] = {
        (char*)f->ipset_bin, (char*)"add", (char*)"wgate_filterd",
        ipbuf, (char*)"timeout", timeout_s, (char*)"-exist", NULL
    };
    int rc = run_ipset_argv(f->ipset_bin, argv);
    if (rc != 0) LOG_W("ipset add wgate_filterd %s: rc=%d", ipbuf, rc);
}

/* --------------------------- new/free ---------------------------- */

wg_filterd_t *filterd_new(const char *path, const char *ipset_bin,
                          const char *legacy_path) {
    wg_filterd_t *f = calloc(1, sizeof(*f));
    if (!f) return NULL;
    if (path)        strncpy(f->path,        path,        sizeof(f->path)        - 1);
    if (ipset_bin)   strncpy(f->ipset_bin,   ipset_bin,   sizeof(f->ipset_bin)   - 1);
    if (legacy_path) strncpy(f->legacy_path, legacy_path, sizeof(f->legacy_path) - 1);
    return f;
}

void filterd_free(wg_filterd_t *f) {
    if (!f) return;
    for (size_t i = 0; i < f->n_targets; i++) free(f->targets[i]);
    free(f->targets);
    free(f);
}

/* ---------------------------- targets ---------------------------- */

static void grow_targets(wg_filterd_t *f) {
    if (f->n_targets < f->cap_targets) return;
    if (f->cap_targets >= FILTERD_TARGETS_MAX) return;
    size_t nc = f->cap_targets ? f->cap_targets * 2 : 16;
    if (nc > FILTERD_TARGETS_MAX) nc = FILTERD_TARGETS_MAX;
    char **n = realloc(f->targets, nc * sizeof(*n));
    if (!n) return;
    f->targets = n;
    f->cap_targets = nc;
}

static int load_array_from(wg_filterd_t *f, const char *path) {
    size_t n = 0;
    char *buf = read_small_file(path, 64 * 1024, &n);
    if (!buf) return 0;
    const char *err = NULL;
    json_val_t *v = json_parse(buf, n, &err);
    free(buf);
    if (!v) {
        LOG_W("filterd: parse %s: %s", path, err ? err : "?");
        return -1;
    }
    if (v->type != JV_ARR) { json_val_free(v); return -1; }
    int loaded = 0;
    for (size_t i = 0; i < v->u.arr.n; i++) {
        const json_val_t *e = &v->u.arr.items[i];
        if (e->type != JV_STR) continue;
        char *dup = dup_lower(e->u.str.s);
        if (!dup) continue;
        grow_targets(f);
        if (f->n_targets >= f->cap_targets) { free(dup); continue; }
        f->targets[f->n_targets++] = dup;
        loaded++;
    }
    json_val_free(v);
    return loaded;
}

int filterd_load(wg_filterd_t *f) {
    if (!f) return -1;
    for (size_t i = 0; i < f->n_targets; i++) free(f->targets[i]);
    f->n_targets = 0;

    bool primary_exists = false;
    if (f->path[0]) {
        if (access(f->path, F_OK) == 0) primary_exists = true;
    }

    if (primary_exists) {
        load_array_from(f, f->path);
    } else if (!f->legacy_consumed && f->legacy_path[0] &&
               access(f->legacy_path, F_OK) == 0) {
        LOG_I("filterd: legacy %s found; loading once. "
              "Rename to %s to silence this.", f->legacy_path, f->path);
        load_array_from(f, f->legacy_path);
        f->legacy_consumed = true;
        f->dirty = true;   /* persist into the new path on first save */
    }

    f->dirty = f->dirty || !primary_exists;
    return 0;
}

int filterd_save(wg_filterd_t *f) {
    if (!f || !f->path[0]) return 0;
    if (!f->dirty) return 0;
    json_out_t j;
    json_out_init(&j);
    json_arr_begin(&j);
    for (size_t i = 0; i < f->n_targets; i++) json_str(&j, f->targets[i]);
    json_arr_end(&j);
    int rc = atomic_write(f->path,
                          j.buf ? j.buf : "[]",
                          j.buf ? j.len : 2);
    json_out_free(&j);
    if (rc == 0) f->dirty = false;
    return rc;
}

/* ---------------------------- matching --------------------------- */

bool filterd_domain_matches(const wg_filterd_t *f, const char *domain) {
    if (!f || !domain || !*domain) return false;
    char lo[128];
    size_t dn = strlen(domain);
    if (dn >= sizeof(lo)) dn = sizeof(lo) - 1;
    for (size_t i = 0; i < dn; i++) lo[i] = (char)tolower((unsigned char)domain[i]);
    lo[dn] = 0;
    for (size_t i = 0; i < f->n_targets; i++) {
        if (label_suffix_match(lo, f->targets[i])) return true;
    }
    return false;
}

/* --------------------------- observe + flush ---------------------- */

void filterd_observe_ip(wg_filterd_t *f, uint32_t ip) {
    if (!f || ip == 0) return;
    /* Cheap dedupe against the most-recently-pushed entries — keeps a
     * burst of identical answers from filling the ring. */
    size_t lookback = f->pending_n < 8 ? f->pending_n : 8;
    for (size_t i = 0; i < lookback; i++) {
        size_t idx = (f->pending_n - 1 - i) % FILTERD_PENDING_CAP;
        if (f->pending[idx] == ip) return;
    }
    if (f->pending_n < FILTERD_PENDING_CAP) {
        f->pending[f->pending_n++] = ip;
    } else {
        /* full: overwrite the oldest slot, then bump tail */
        memmove(&f->pending[0], &f->pending[1],
                (FILTERD_PENDING_CAP - 1) * sizeof(uint32_t));
        f->pending[FILTERD_PENDING_CAP - 1] = ip;
    }
}

void filterd_flush(wg_filterd_t *f, int64_t now_wall) {
    (void)now_wall;
    if (!f || f->pending_n == 0) return;
    for (size_t i = 0; i < f->pending_n; i++) ipset_add_filterd(f, f->pending[i]);
    f->pending_n = 0;
}

/* --------------------------- target CRUD -------------------------- */

static int find_target_idx(const wg_filterd_t *f, const char *lo) {
    for (size_t i = 0; i < f->n_targets; i++) {
        if (strcmp(f->targets[i], lo) == 0) return (int)i;
    }
    return -1;
}

int filterd_add_target(wg_filterd_t *f, const char *domain) {
    if (!f || !domain || !*domain) return 0;
    char *lo = dup_lower(domain);
    if (!lo) return 0;
    if (find_target_idx(f, lo) >= 0) { free(lo); return 0; }
    if (f->n_targets >= FILTERD_TARGETS_MAX) {
        LOG_W("filterd: targets at cap (%d); refusing add %s",
              FILTERD_TARGETS_MAX, lo);
        free(lo);
        return 0;
    }
    grow_targets(f);
    if (f->n_targets >= f->cap_targets) { free(lo); return 0; }
    f->targets[f->n_targets++] = lo;
    f->dirty = true;
    filterd_save(f);
    return 1;
}

int filterd_remove_target(wg_filterd_t *f, const char *domain) {
    if (!f || !domain) return 0;
    char *lo = dup_lower(domain);
    if (!lo) return 0;
    int idx = find_target_idx(f, lo);
    free(lo);
    if (idx < 0) return 0;
    free(f->targets[idx]);
    memmove(&f->targets[idx], &f->targets[idx+1],
            (f->n_targets - (size_t)idx - 1) * sizeof(*f->targets));
    f->n_targets--;
    f->dirty = true;
    filterd_save(f);
    return 1;
}

/* ------------------------- JSON dump ----------------------------- */

void filterd_dump_json(const wg_filterd_t *f, json_out_t *j) {
    json_obj_begin(j);
    json_key(j, "targets");
    json_arr_begin(j);
    if (f) for (size_t i = 0; i < f->n_targets; i++) json_str(j, f->targets[i]);
    json_arr_end(j);
    json_obj_end(j);
}
