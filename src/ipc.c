#include "ipc.h"
#include "arp_bind.h"
#include "dnsmasq_conf.h"
#include "filterd.h"
#include "json.h"
#include "log.h"
#include "metrics.h"
#include "pins.h"
#include "schedule.h"
#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define IPC_MAX_CLIENTS   16
#define IPC_HDR_CAP       8192
#define IPC_BODY_CAP      (64 * 1024)
#define IPC_CLIENT_TIMEOUT_NS  (10ull * 1000000000ull)   /* 10 seconds */

typedef enum {
    ST_READ_HDR,
    ST_READ_BODY,
    ST_WRITE_RESP,
    ST_DONE
} client_state_t;

typedef struct {
    int             fd;
    client_state_t  st;
    char            hdr[IPC_HDR_CAP];
    size_t          hdr_len;
    char           *body;
    size_t          body_len;
    size_t          content_length;
    char            method[8];
    char            path[256];
    char            raw_path[256];   /* path including query string */
    char           *resp;
    size_t          resp_len;
    size_t          resp_off;
    bool            is_new;
    uint64_t        deadline_ns;     /* CLOCK_MONOTONIC; 0 = none */
} client_t;

struct wg_ipc {
    int            listen_fd;
    client_t       clients[IPC_MAX_CLIENTS];
    wg_ipc_app_t  *app;
};

/* -------------------- helpers -------------------- */

static void client_reset(client_t *c) {
    if (c->fd >= 0) close(c->fd);
    free(c->body);
    free(c->resp);
    memset(c, 0, sizeof(*c));
    c->fd = -1;
}

static client_t *client_slot(wg_ipc_t *ipc) {
    for (int i = 0; i < IPC_MAX_CLIENTS; i++)
        if (ipc->clients[i].fd < 0) return &ipc->clients[i];
    return NULL;
}

static client_t *client_by_fd(wg_ipc_t *ipc, int fd) {
    for (int i = 0; i < IPC_MAX_CLIENTS; i++)
        if (ipc->clients[i].fd == fd) return &ipc->clients[i];
    return NULL;
}

static void client_touch(client_t *c) {
    c->deadline_ns = now_mono_ns() + IPC_CLIENT_TIMEOUT_NS;
}

/* -------------------- response building -------------------- */

static void build_response(client_t *c, int status, const char *status_text,
                           const char *ctype, const char *body, size_t blen) {
    const char *st_txt = status_text ? status_text :
        status == 200 ? "OK" :
        status == 400 ? "Bad Request" :
        status == 404 ? "Not Found" :
        status == 405 ? "Method Not Allowed" :
        status == 413 ? "Payload Too Large" :
        status == 415 ? "Unsupported Media Type" :
        status == 500 ? "Internal Server Error" : "OK";
    const char *ct = ctype ? ctype : "application/json";

    size_t hcap = 512;
    char *buf = malloc(hcap + blen);
    if (!buf) return;
    int n = snprintf(buf, hcap,
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        status, st_txt, ct, blen);
    if (n < 0 || (size_t)n >= hcap) { free(buf); return; }
    if (blen && body) memcpy(buf + n, body, blen);
    c->resp     = buf;
    c->resp_len = (size_t)n + blen;
    c->resp_off = 0;
    c->st       = ST_WRITE_RESP;
}

static void respond_json(client_t *c, int status, const json_out_t *j) {
    build_response(c, status, NULL, "application/json",
                   j->buf ? j->buf : "{}", j->buf ? j->len : 2);
}

static void respond_simple(client_t *c, int status, const char *msg) {
    json_out_t j;
    json_out_init(&j);
    json_obj_begin(&j);
    json_kbool(&j, "ok", status == 200);
    if (msg && *msg) json_kstr(&j, "error", msg);
    json_obj_end(&j);
    respond_json(c, status, &j);
    json_out_free(&j);
}

/* -------------------- request parsing -------------------- */

static int parse_headers(client_t *c, size_t *body_off_out) {
    char *p = memmem(c->hdr, c->hdr_len, "\r\n\r\n", 4);
    if (!p) return 0;
    size_t hdr_end = (size_t)(p - c->hdr) + 4;

    char *sp1 = memchr(c->hdr, ' ', hdr_end);
    if (!sp1) return -1;
    size_t mlen = (size_t)(sp1 - c->hdr);
    if (mlen == 0 || mlen >= sizeof(c->method)) return -1;
    memcpy(c->method, c->hdr, mlen);
    c->method[mlen] = 0;

    char *sp2 = memchr(sp1 + 1, ' ', hdr_end - (size_t)(sp1 + 1 - c->hdr));
    if (!sp2) return -1;
    size_t plen = (size_t)(sp2 - sp1 - 1);
    if (plen == 0 || plen >= sizeof(c->path)) return -1;
    memcpy(c->raw_path, sp1 + 1, plen);
    c->raw_path[plen] = 0;
    memcpy(c->path, c->raw_path, plen + 1);
    /* strip query string from c->path */
    char *q = strchr(c->path, '?');
    if (q) *q = 0;

    c->content_length = 0;
    const char *h = c->hdr;
    const char *end = c->hdr + hdr_end;
    while (h < end) {
        const char *nl = memchr(h, '\n', (size_t)(end - h));
        if (!nl) break;
        if ((size_t)(nl - h) >= 15 &&
            strncasecmp(h, "content-length:", 15) == 0) {
            const char *v = h + 15;
            while (v < nl && (*v == ' ' || *v == '\t')) v++;
            char tmp[32];
            size_t n = (size_t)(nl - v);
            if (n && n < sizeof(tmp)) {
                memcpy(tmp, v, n);
                tmp[n] = 0;
                while (n > 0 && (tmp[n-1] == '\r' || tmp[n-1] == ' ')) tmp[--n] = 0;
                c->content_length = (size_t)strtoul(tmp, NULL, 10);
            }
        }
        h = nl + 1;
    }
    if (c->content_length > IPC_BODY_CAP) return -1;
    *body_off_out = hdr_end;
    return 1;
}

/* -------------------- query helpers -------------------- */

static const char *query_string(const client_t *c) {
    const char *q = strchr(c->raw_path, '?');
    return q ? q + 1 : NULL;
}

/* In-place percent-decode. Rejects embedded NUL (%00): the input stays
 * unchanged and the first byte becomes 0 so the caller's string-based
 * consumers see it as empty. */
static void url_decode(char *s) {
    char *r = s, *w = s;
    while (*r) {
        if (*r == '%' && r[1] && r[2]) {
            char h1 = r[1], h2 = r[2];
            int v1 = (h1 >= '0' && h1 <= '9') ? h1 - '0'
                   : (h1 >= 'a' && h1 <= 'f') ? h1 - 'a' + 10
                   : (h1 >= 'A' && h1 <= 'F') ? h1 - 'A' + 10 : -1;
            int v2 = (h2 >= '0' && h2 <= '9') ? h2 - '0'
                   : (h2 >= 'a' && h2 <= 'f') ? h2 - 'a' + 10
                   : (h2 >= 'A' && h2 <= 'F') ? h2 - 'A' + 10 : -1;
            if (v1 >= 0 && v2 >= 0) {
                char b = (char)((v1 << 4) | v2);
                if (b == 0) { s[0] = 0; return; }   /* reject %00 */
                *w++ = b;
                r += 3;
                continue;
            }
        }
        *w++ = *r++;
    }
    *w = 0;
}

static char *query_get(const char *qs, const char *key) {
    if (!qs) return NULL;
    size_t kl = strlen(key);
    const char *p = qs;
    while (*p) {
        const char *amp = strchr(p, '&');
        size_t segn = amp ? (size_t)(amp - p) : strlen(p);
        if (segn > kl && p[kl] == '=' && strncmp(p, key, kl) == 0) {
            size_t vl = segn - kl - 1;
            char *v = malloc(vl + 1);
            if (!v) return NULL;
            memcpy(v, p + kl + 1, vl);
            v[vl] = 0;
            url_decode(v);
            return v;
        }
        if (!amp) break;
        p = amp + 1;
    }
    return NULL;
}

/* -------------------- iptables-reconcile after change ----------------- */

/* Ask the supervisor loop in main.c to re-apply iptables. The callback
 * is expected to coalesce requests (at most one actual iptables pass
 * every few seconds) so that an API spammer cannot flood the netfilter
 * fast path. */
static void do_reconcile(wg_ipc_app_t *app) {
    if (app && app->reconcile_request_cb)
        app->reconcile_request_cb(app->reconcile_cb_arg);
}

/* -------------------- handlers -------------------- */

static void handle_status(wg_ipc_t *ipc, client_t *c) {
    json_out_t j;
    json_out_init(&j);
    json_obj_begin(&j);
    json_kbool(&j, "ok", true);
    /* uptime reflects the host kernel, not the daemon process — the
     * agent cares about box health, not whether wgatectl just
     * restarted for a config reload. */
    json_ki64(&j, "uptime_s",   now_boot_s());
    json_ki64(&j, "lease_count", (int)ipc->app->leases->n);
    int64_t now = now_wall_s();
    json_ki64(&j, "pins_count",  (int)pins_count(ipc->app->pins, now));
    json_kstr(&j, "iface",   ipc->app->cfg->iface);
    json_kstr(&j, "network", ipc->app->cfg->network_cidr);
    int64_t next = 0;
    sch_mode_t mode = schedule_effective_mode(ipc->app->sched, now, &next);
    json_kstr(&j, "mode", sch_mode_name(mode));
    if (next) json_ki64(&j, "next_transition", next);
    json_obj_end(&j);
    respond_json(c, 200, &j);
    json_out_free(&j);
}

static void handle_hosts(wg_ipc_t *ipc, client_t *c) {
    const wg_leases_t *leases = ipc->app->leases;
    const wg_pins_t   *pins   = ipc->app->pins;
    int64_t now = now_wall_s();

    json_out_t j;
    json_out_init(&j);
    json_arr_begin(&j);

    for (size_t i = 0; i < leases->n; i++) {
        const wg_lease_t *l = &leases->items[i];
        char ipbuf[16], macbuf[18];
        ip_format(l->ip, ipbuf);
        mac_format(l->mac, macbuf);
        bool pinned = false;
        sch_mode_t pmode = pins_for_ip(pins, leases, l->ip, now, &pinned);
        json_obj_begin(&j);
        if (l->name[0]) json_kstr(&j, "name", l->name);
        else            json_knull(&j, "name");
        json_kstr (&j, "ip",  ipbuf);
        json_kstr (&j, "mac", macbuf);
        json_kbool(&j, "is_static", l->is_static);
        json_kbool(&j, "pinned", pinned);
        if (pinned) json_kstr(&j, "pin_mode", sch_mode_name(pmode));
        if (l->first_seen) json_ki64(&j, "first_seen_unix", l->first_seen);
        if (l->last_seen)  json_ki64(&j, "last_seen_unix",  l->last_seen);
        json_obj_end(&j);
    }
    json_arr_end(&j);
    respond_json(c, 200, &j);
    json_out_free(&j);
}

/* Extract "/hosts/<key>/<action>" → key, action. Returns action pointer. */
static const char *path_after_key(const char *path, const char *prefix,
                                  char *key_out, size_t key_cap) {
    size_t pl = strlen(prefix);
    if (strncmp(path, prefix, pl) != 0) return NULL;
    const char *p = path + pl;
    const char *slash = strchr(p, '/');
    if (!slash) return NULL;
    size_t kl = (size_t)(slash - p);
    if (kl == 0 || kl >= key_cap) return NULL;
    memcpy(key_out, p, kl);
    key_out[kl] = 0;
    return slash + 1;
}

/* POST /hosts/<key>/name?name=<new>
 *   Set a DHCP-reservation name for the device identified by <key>.
 *   <key> must resolve to a lease with a known MAC (either an existing
 *   dhcp-host entry or a live DHCP lease). The new name must be valid
 *   DNS-ish and not already in use by another device. On success we
 *   rewrite dnsmasq.conf atomically, refresh the in-memory leases +
 *   ARP pins, and schedule a debounced dnsmasq reload. */
static void handle_host_name(wg_ipc_t *ipc, client_t *c, const char *key) {
    wg_ipc_app_t *app = ipc->app;
    char *newname = query_get(query_string(c), "name");
    if (!newname || !*newname) {
        free(newname);
        respond_simple(c, 400, "name required");
        return;
    }

    /* Resolve key → lease. Accept IP, existing name, or MAC text. */
    const wg_lease_t *l = NULL;
    uint32_t ip;
    uint8_t mac_from_key[6];
    if (ip_parse(key, &ip))             l = leases_by_ip  (app->leases, ip);
    else if (mac_parse(key, mac_from_key)) {
        for (size_t i = 0; i < app->leases->n; i++) {
            if (memcmp(app->leases->items[i].mac, mac_from_key, 6) == 0) {
                l = &app->leases->items[i]; break;
            }
        }
    } else                              l = leases_by_name(app->leases, key);

    if (!l) {
        free(newname);
        respond_simple(c, 404, "unknown host");
        return;
    }
    uint8_t zero[6] = {0};
    if (memcmp(l->mac, zero, 6) == 0) {
        free(newname);
        respond_simple(c, 400, "host has no known MAC");
        return;
    }

    /* In-memory uniqueness check: any other lease already using this name? */
    for (size_t i = 0; i < app->leases->n; i++) {
        const wg_lease_t *o = &app->leases->items[i];
        if (memcmp(o->mac, l->mac, 6) == 0) continue;
        if (o->name[0] && strcmp(o->name, newname) == 0) {
            free(newname);
            respond_simple(c, 409, "name already in use");
            return;
        }
    }

    bool changed = false;
    dnsmasq_name_rc_t rc = dnsmasq_set_host_name(app->cfg->dnsmasq_conf,
                                                 l->mac, l->ip, newname,
                                                 &changed);
    if (rc != DNS_NAME_OK) {
        const char *msg =
            rc == DNS_NAME_INVALID   ? "invalid name" :
            rc == DNS_NAME_DUPLICATE ? "name already in use" :
            rc == DNS_NAME_NO_MAC    ? "host has no known MAC" :
                                       "dnsmasq.conf write failed";
        int status = (rc == DNS_NAME_DUPLICATE) ? 409
                   : (rc == DNS_NAME_INVALID || rc == DNS_NAME_NO_MAC) ? 400
                   : 500;
        free(newname);
        respond_simple(c, status, msg);
        return;
    }

    if (changed) {
        leases_reload(app->leases, app->cfg->dnsmasq_conf,
                      app->cfg->dnsmasq_leases, app->cfg->static_cidr);
        if (app->ab) arp_bind_apply(app->ab, app->leases);
        if (app->dnsmasq_reload_request_cb)
            app->dnsmasq_reload_request_cb(app->dnsmasq_reload_cb_arg);
        char ipbuf[16] = "";
        if (l->ip) ip_format(l->ip, ipbuf);
        metrics_emit_control(app->jl, now_wall_s(), newname,
                             ipbuf[0] ? ipbuf : NULL, "rename", "api");
    }

    json_out_t j; json_out_init(&j);
    json_obj_begin(&j);
    json_kbool(&j, "ok", true);
    json_kstr (&j, "name", newname);
    json_kbool(&j, "changed", changed);
    json_obj_end(&j);
    respond_json(c, 200, &j);
    json_out_free(&j);
    free(newname);
}

/* Forward decl: handle_host_mode_set is defined further down (with the
 * other pin handlers) but is referenced from the action dispatcher. */
static void handle_host_mode_set(wg_ipc_t *ipc, client_t *c, const char *key);

static void handle_host_action(wg_ipc_t *ipc, client_t *c,
                               const char *key, const char *action) {
    if (strcmp(action, "name") == 0) { handle_host_name    (ipc, c, key); return; }
    if (strcmp(action, "mode") == 0) { handle_host_mode_set(ipc, c, key); return; }
    respond_simple(c, 404, "unknown action");
}

/* --------------------- schedule handlers ----------------------- */

static void handle_schedule_get(wg_ipc_t *ipc, client_t *c) {
    json_out_t j;
    json_out_init(&j);
    schedule_dump_json(ipc->app->sched, now_wall_s(), &j);
    respond_json(c, 200, &j);
    json_out_free(&j);
}

/* Extract path suffix after `prefix` into `out`; returns false if the
 * suffix is empty. Trims a trailing slash. */
static bool path_suffix(const char *path, const char *prefix,
                        char *out, size_t cap) {
    size_t pl = strlen(prefix);
    if (strncmp(path, prefix, pl) != 0) return false;
    const char *s = path + pl;
    if (!*s) return false;
    size_t n = strlen(s);
    while (n && s[n-1] == '/') n--;
    if (!n || n >= cap) return false;
    memcpy(out, s, n);
    out[n] = 0;
    return true;
}

static void handle_override_add(wg_ipc_t *ipc, client_t *c) {
    wg_ipc_app_t *app = ipc->app;
    if (!c->body || c->body_len == 0) {
        respond_simple(c, 400, "body required");
        return;
    }
    const char *err = NULL;
    json_val_t *v = json_parse(c->body, c->body_len, &err);
    if (!v || v->type != JV_OBJ) {
        if (v) json_val_free(v);
        respond_simple(c, 400, err ? err : "bad json");
        return;
    }
    int64_t at = 0, expires_at = 0;
    const char *mode_str = NULL, *reason = NULL;
    json_get_i64(json_obj_get(v, "at"),         &at);
    json_get_i64(json_obj_get(v, "expires_at"), &expires_at);
    json_get_str(json_obj_get(v, "mode"),       &mode_str);
    json_get_str(json_obj_get(v, "reason"),     &reason);

    sch_mode_t m;
    if (!sch_mode_parse(mode_str, &m)) {
        json_val_free(v);
        respond_simple(c, 400, "mode must be closed|filtered|open");
        return;
    }
    if (at == 0) at = now_wall_s();
    if (expires_at && expires_at <= at) {
        json_val_free(v);
        respond_simple(c, 400, "expires_at must be > at");
        return;
    }

    char id[24];
    int rc = schedule_override_add(app->sched, at, m, expires_at, reason,
                                   id, sizeof(id));
    json_val_free(v);
    if (rc < 0) { respond_simple(c, 500, "override add failed"); return; }

    do_reconcile(app);
    metrics_emit_control(app->jl, now_wall_s(), "dhcp-range", NULL,
                         sch_mode_name(m), "api");

    json_out_t j; json_out_init(&j);
    json_obj_begin(&j);
    json_kbool(&j, "ok", true);
    json_kstr (&j, "id", id);
    json_obj_end(&j);
    respond_json(c, 200, &j);
    json_out_free(&j);
}

static void handle_override_remove(wg_ipc_t *ipc, client_t *c,
                                   const char *id) {
    wg_ipc_app_t *app = ipc->app;
    int removed = schedule_override_remove(app->sched, id);
    if (removed) do_reconcile(app);
    json_out_t j; json_out_init(&j);
    json_obj_begin(&j);
    json_kbool(&j, "ok", true);
    json_kbool(&j, "changed", removed != 0);
    json_obj_end(&j);
    respond_json(c, 200, &j);
    json_out_free(&j);
}

static void handle_mode_force(wg_ipc_t *ipc, client_t *c,
                              const char *mode_str) {
    wg_ipc_app_t *app = ipc->app;
    sch_mode_t m;
    if (!sch_mode_parse(mode_str, &m)) {
        respond_simple(c, 404, "unknown mode");
        return;
    }
    int64_t now = now_wall_s();
    int64_t expires_at = 0;
    char *until = query_get(query_string(c), "until");
    if (until) {
        expires_at = strtoll(until, NULL, 10);
        free(until);
        if (expires_at && expires_at <= now) {
            respond_simple(c, 400, "until must be in the future");
            return;
        }
    }
    char *reason = query_get(query_string(c), "reason");
    char id[24];
    int rc = schedule_override_add(app->sched, now, m, expires_at, reason,
                                   id, sizeof(id));
    free(reason);
    if (rc < 0) { respond_simple(c, 500, "override add failed"); return; }

    do_reconcile(app);
    metrics_emit_control(app->jl, now, "dhcp-range", NULL,
                         sch_mode_name(m), "api");

    json_out_t j; json_out_init(&j);
    json_obj_begin(&j);
    json_kbool(&j, "ok", true);
    json_kstr (&j, "mode", sch_mode_name(m));
    json_kstr (&j, "id", id);
    if (expires_at) json_ki64(&j, "expires_at", expires_at);
    json_obj_end(&j);
    respond_json(c, 200, &j);
    json_out_free(&j);
}

/* --------------------- filterd handlers ---------------------- */

static void handle_filtered_list(wg_ipc_t *ipc, client_t *c) {
    json_out_t j;
    json_out_init(&j);
    filterd_dump_json(ipc->app->filterd, &j);
    respond_json(c, 200, &j);
    json_out_free(&j);
}

static void handle_filtered_add(wg_ipc_t *ipc, client_t *c,
                                const char *domain) {
    int changed = filterd_add_target(ipc->app->filterd, domain);
    json_out_t j; json_out_init(&j);
    json_obj_begin(&j);
    json_kbool(&j, "ok", true);
    json_kstr (&j, "target", domain);
    json_kbool(&j, "changed", changed != 0);
    json_obj_end(&j);
    respond_json(c, 200, &j);
    json_out_free(&j);
}

static void handle_filtered_remove(wg_ipc_t *ipc, client_t *c,
                                   const char *domain) {
    int changed = filterd_remove_target(ipc->app->filterd, domain);
    json_out_t j; json_out_init(&j);
    json_obj_begin(&j);
    json_kbool(&j, "ok", true);
    json_kstr (&j, "target", domain);
    json_kbool(&j, "changed", changed != 0);
    json_obj_end(&j);
    respond_json(c, 200, &j);
    json_out_free(&j);
}

/* ---------------------- pin handlers ------------------------ */

/* POST /hosts/<key>/mode  body: {"mode":"closed|filtered|open",
 *                                "minutes":N | "until":<epoch>,
 *                                "reason":"..."}
 *
 *   `until` wins over `minutes` when both are present. The resolved
 *   expiry MUST be > now — pins always have a strict expiry, by
 *   design. Operators wanting permanent allow should add the host to
 *   WG_STATIC_CIDR. */
static void handle_host_mode_set(wg_ipc_t *ipc, client_t *c, const char *key) {
    wg_ipc_app_t *app = ipc->app;
    if (!c->body || c->body_len == 0) {
        respond_simple(c, 400, "body required");
        return;
    }
    const char *err = NULL;
    json_val_t *v = json_parse(c->body, c->body_len, &err);
    if (!v || v->type != JV_OBJ) {
        if (v) json_val_free(v);
        respond_simple(c, 400, err ? err : "bad json");
        return;
    }
    const char *mode_str = NULL, *reason = NULL;
    int64_t until = 0, minutes_i = 0;
    json_get_str(json_obj_get(v, "mode"),    &mode_str);
    json_get_str(json_obj_get(v, "reason"),  &reason);
    json_get_i64(json_obj_get(v, "until"),   &until);
    json_get_i64(json_obj_get(v, "minutes"), &minutes_i);

    sch_mode_t m;
    if (!sch_mode_parse(mode_str, &m)) {
        json_val_free(v);
        respond_simple(c, 400, "mode must be closed|filtered|open");
        return;
    }
    int64_t now = now_wall_s();
    if (until == 0 && minutes_i > 0) until = now + minutes_i * 60;
    if (until <= now) {
        json_val_free(v);
        respond_simple(c, 400, "minutes or until required (must be > now)");
        return;
    }

    int rc = pins_set(app->pins, app->leases, key, m, until, reason);
    if (rc) {
        do_reconcile(app);
        char ipbuf[16] = "";
        uint32_t ip;
        if (leases_resolve_ip(app->leases, key, &ip)) ip_format(ip, ipbuf);
        metrics_emit_control(app->jl, now, key, ipbuf[0] ? ipbuf : NULL,
                             "pin", sch_mode_name(m));
    }

    json_out_t j; json_out_init(&j);
    json_obj_begin(&j);
    json_kbool(&j, "ok", true);
    json_kstr (&j, "host",  key);
    json_kstr (&j, "mode",  sch_mode_name(m));
    json_ki64 (&j, "until", until);
    if (reason && *reason) json_kstr(&j, "reason", reason);
    json_kbool(&j, "changed", rc != 0);
    json_obj_end(&j);
    respond_json(c, 200, &j);
    json_out_free(&j);

    json_val_free(v);
}

/* DELETE /hosts/<key>/mode — remove the active pin (if any). */
static void handle_host_mode_delete(wg_ipc_t *ipc, client_t *c,
                                    const char *key) {
    wg_ipc_app_t *app = ipc->app;
    int removed = pins_remove(app->pins, app->leases, key);
    if (removed) {
        do_reconcile(app);
        metrics_emit_control(app->jl, now_wall_s(), key, NULL,
                             "unpin", "api");
    }
    json_out_t j; json_out_init(&j);
    json_obj_begin(&j);
    json_kbool(&j, "ok", true);
    json_kbool(&j, "changed", removed != 0);
    json_obj_end(&j);
    respond_json(c, 200, &j);
    json_out_free(&j);
}

static int tail_cb(void *vctx, const char *line, size_t len) {
    json_out_t *out = vctx;
    if (out->len + len + 2 > out->cap) {
        size_t ncap = out->cap ? out->cap : 4096;
        while (ncap < out->len + len + 2) ncap *= 2;
        char *nb = realloc(out->buf, ncap);
        if (!nb) return -1;
        out->buf = nb;
        out->cap = ncap;
    }
    memcpy(out->buf + out->len, line, len);
    out->len += len;
    out->buf[out->len++] = '\n';
    out->buf[out->len]   = 0;
    return 0;
}

static void handle_metrics_tail(wg_ipc_t *ipc, client_t *c) {
    char *since = query_get(query_string(c), "since");
    long since_ts = since ? strtol(since, NULL, 10) : 0;
    free(since);

    json_out_t out; json_out_init(&out);
    jsonl_tail(ipc->app->jl, since_ts, tail_cb, &out);
    build_response(c, 200, NULL, "application/x-ndjson",
                   out.buf ? out.buf : "", out.buf ? out.len : 0);
    json_out_free(&out);
}

static void handle_reload(wg_ipc_t *ipc, client_t *c) {
    wg_ipc_app_t *app = ipc->app;
    leases_reload(app->leases, app->cfg->dnsmasq_conf, app->cfg->dnsmasq_leases,
                  app->cfg->static_cidr);
    if (app->ab) arp_bind_apply(app->ab, app->leases);
    schedule_load(app->sched);
    filterd_load(app->filterd);
    pins_load(app->pins);
    do_reconcile(app);
    respond_simple(c, 200, NULL);
}

/* -------------------- pve status / wake -------------------- */

/* /pve probes pve, mint, and twin via parallel `ping -c 1 -W 1`. The
 * names are looked up in the leases table (dnsmasq sees them as static
 * hosts). pve is the Proxmox box; mint and twin are GPU-passthrough VMs
 * that share the GPU and so are mutually exclusive. */
static const char *const PVE_PROBE_NAMES[] = { "pve", "mint", "twin" };
#define PVE_PROBE_N ((int)(sizeof(PVE_PROBE_NAMES) / sizeof(PVE_PROBE_NAMES[0])))

static void handle_pve_status(wg_ipc_t *ipc, client_t *c) {
    const wg_leases_t *leases = ipc->app->leases;

    char ipbuf[PVE_PROBE_N][16];
    pid_t pids[PVE_PROBE_N] = { 0 };
    int   up  [PVE_PROBE_N] = { 0 };
    int   has [PVE_PROBE_N] = { 0 };

    for (int i = 0; i < PVE_PROBE_N; i++) {
        const wg_lease_t *l = leases_by_name(leases, PVE_PROBE_NAMES[i]);
        if (!l) continue;
        has[i] = 1;
        ip_format(l->ip, ipbuf[i]);

        pid_t pid = fork();
        if (pid < 0) {
            LOG_W("pve: fork: %s", strerror(errno));
            continue;
        }
        if (pid == 0) {
            char cmd[96];
            snprintf(cmd, sizeof(cmd),
                     "exec ping -c 1 -W 1 -n -q %s >/dev/null 2>&1",
                     ipbuf[i]);
            execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
            _exit(127);
        }
        pids[i] = pid;
    }

    for (int i = 0; i < PVE_PROBE_N; i++) {
        if (!pids[i]) continue;
        int status = 0;
        while (waitpid(pids[i], &status, 0) < 0) {
            if (errno != EINTR) break;
        }
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) up[i] = 1;
    }

    json_out_t j;
    json_out_init(&j);
    json_obj_begin(&j);
    json_kbool(&j, "ok", true);
    json_key(&j, "hosts");
    json_arr_begin(&j);
    for (int i = 0; i < PVE_PROBE_N; i++) {
        json_obj_begin(&j);
        json_kstr(&j, "name", PVE_PROBE_NAMES[i]);
        if (has[i]) {
            json_kstr(&j, "ip", ipbuf[i]);
            json_kstr(&j, "status", up[i] ? "up" : "down");
        } else {
            json_knull(&j, "ip");
            json_kstr(&j, "status", "unknown");
        }
        json_obj_end(&j);
    }
    json_arr_end(&j);
    json_obj_end(&j);
    respond_json(c, 200, &j);
    json_out_free(&j);
}

/* Built-in WoL: 6 x 0xFF + 16 x MAC, sent as UDP/9 to the LAN broadcast.
 * Bound to the LAN iface so the packet definitely leaves the right NIC
 * regardless of routing table state. */
static void handle_pve_wake(wg_ipc_t *ipc, client_t *c) {
    const wg_cfg_t *cfg = ipc->app->cfg;

    if (cfg->pve_mac[0] == 0) {
        respond_simple(c, 400, "WG_PVE_MAC not set");
        return;
    }
    uint8_t mac[6];
    if (!mac_parse(cfg->pve_mac, mac)) {
        respond_simple(c, 400, "invalid WG_PVE_MAC");
        return;
    }

    uint8_t pkt[6 + 16 * 6];
    memset(pkt, 0xFF, 6);
    for (int i = 0; i < 16; i++) memcpy(pkt + 6 + i * 6, mac, 6);

    int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s < 0) { respond_simple(c, 500, strerror(errno)); return; }

    int yes = 1;
    if (setsockopt(s, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(yes)) < 0) {
        int e = errno; close(s);
        respond_simple(c, 500, strerror(e));
        return;
    }
    if (cfg->iface[0]) {
        if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE,
                       cfg->iface, (socklen_t)strlen(cfg->iface)) < 0) {
            LOG_W("pve wake: SO_BINDTODEVICE %s: %s",
                  cfg->iface, strerror(errno));
            /* fall through; routing should still pick the right iface */
        }
    }

    uint32_t bcast = cfg->net_addr | ~cfg->net_mask;
    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family      = AF_INET;
    to.sin_port        = htons(9);
    to.sin_addr.s_addr = htonl(bcast);

    ssize_t n = sendto(s, pkt, sizeof(pkt), 0,
                       (struct sockaddr *)&to, sizeof(to));
    int saved = errno;
    close(s);
    if (n != (ssize_t)sizeof(pkt)) {
        respond_simple(c, 500, strerror(saved));
        return;
    }

    char macbuf[18], bcbuf[16];
    mac_format(mac, macbuf);
    ip_format(bcast, bcbuf);
    LOG_I("pve wake: sent magic packet to %s via %s on %s",
          macbuf, bcbuf, cfg->iface);

    json_out_t j;
    json_out_init(&j);
    json_obj_begin(&j);
    json_kbool(&j, "ok", true);
    json_kstr (&j, "mac",       macbuf);
    json_kstr (&j, "broadcast", bcbuf);
    json_kstr (&j, "iface",     cfg->iface);
    json_obj_end(&j);
    respond_json(c, 200, &j);
    json_out_free(&j);
}

/* -------------------- route dispatch -------------------- */

static void dispatch(wg_ipc_t *ipc, client_t *c) {
    char keybuf[128];
    char suffix[128];
    const char *action;
    const char *m = c->method;
    const char *p = c->path;

    if (strcmp(m, "GET") == 0) {
        if (strcmp(p, "/status")       == 0) { handle_status(ipc, c);       return; }
        if (strcmp(p, "/pve")          == 0) { handle_pve_status(ipc, c);   return; }
        if (strcmp(p, "/hosts")        == 0) { handle_hosts(ipc, c);        return; }
        if (strcmp(p, "/schedule")     == 0) { handle_schedule_get(ipc, c); return; }
        if (strcmp(p, "/filtered")     == 0) { handle_filtered_list(ipc, c); return; }
        if (strcmp(p, "/metrics/tail") == 0) { handle_metrics_tail(ipc, c); return; }
        respond_simple(c, 404, "no such route");
        return;
    }

    if (strcmp(m, "POST") == 0) {
        if ((action = path_after_key(p, "/hosts/", keybuf, sizeof(keybuf))) != NULL) {
            handle_host_action(ipc, c, keybuf, action); return;
        }
        if (strcmp(p, "/schedule/override") == 0) {
            handle_override_add(ipc, c); return;
        }
        if (path_suffix(p, "/mode/", suffix, sizeof(suffix))) {
            handle_mode_force(ipc, c, suffix); return;
        }
        if (path_suffix(p, "/filtered/", suffix, sizeof(suffix))) {
            handle_filtered_add(ipc, c, suffix); return;
        }
        if (strcmp(p, "/reload")   == 0) { handle_reload(ipc, c);   return; }
        if (strcmp(p, "/pve/wake") == 0) { handle_pve_wake(ipc, c); return; }
        respond_simple(c, 404, "no such route");
        return;
    }

    if (strcmp(m, "DELETE") == 0) {
        if (path_suffix(p, "/schedule/override/", suffix, sizeof(suffix))) {
            handle_override_remove(ipc, c, suffix); return;
        }
        if ((action = path_after_key(p, "/hosts/", keybuf, sizeof(keybuf))) != NULL) {
            if (strcmp(action, "mode") == 0) {
                handle_host_mode_delete(ipc, c, keybuf); return;
            }
        }
        if (path_suffix(p, "/filtered/", suffix, sizeof(suffix))) {
            handle_filtered_remove(ipc, c, suffix); return;
        }
        respond_simple(c, 404, "no such route");
        return;
    }

    respond_simple(c, 405, "method not allowed");
}

/* -------------------- accept / event loop -------------------- */

int ipc_accept(wg_ipc_t *ipc) {
    int accepted = 0;
    while (1) {
        int cfd = accept4(ipc->listen_fd, NULL, NULL,
                          SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (cfd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (errno == EINTR) continue;
            LOG_W("accept4: %s", strerror(errno));
            break;
        }
        client_t *c = client_slot(ipc);
        if (!c) { LOG_W("ipc: too many clients, rejecting fd %d", cfd); close(cfd); continue; }
        memset(c, 0, sizeof(*c));
        c->fd = cfd;
        c->st = ST_READ_HDR;
        c->is_new = true;
        client_touch(c);
        accepted++;
    }
    return accepted;
}

int ipc_next_new_client(wg_ipc_t *ipc) {
    for (int i = 0; i < IPC_MAX_CLIENTS; i++) {
        if (ipc->clients[i].fd >= 0 && ipc->clients[i].is_new) {
            ipc->clients[i].is_new = false;
            return ipc->clients[i].fd;
        }
    }
    return -1;
}

int ipc_owns_fd(const wg_ipc_t *ipc, int fd) {
    for (int i = 0; i < IPC_MAX_CLIENTS; i++)
        if (ipc->clients[i].fd == fd) return 1;
    return 0;
}

static int do_read_hdr(client_t *c) {
    ssize_t r = read(c->fd, c->hdr + c->hdr_len, IPC_HDR_CAP - c->hdr_len);
    if (r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        if (errno == EINTR) return 0;
        return -1;
    }
    if (r == 0) return -1;
    client_touch(c);
    c->hdr_len += (size_t)r;

    size_t body_off = 0;
    int pr = parse_headers(c, &body_off);
    if (pr == 0) {
        if (c->hdr_len == IPC_HDR_CAP) {
            build_response(c, 413, NULL, "text/plain", "headers too big\n", 16);
            return 1;
        }
        return 0;
    }
    if (pr < 0) {
        build_response(c, 400, NULL, "text/plain", "bad request\n", 12);
        return 1;
    }
    size_t body_already = c->hdr_len - body_off;
    if (c->content_length > 0) {
        c->body = malloc(c->content_length + 1);
        if (!c->body) return -1;
        if (body_already) {
            if (body_already > c->content_length) body_already = c->content_length;
            memcpy(c->body, c->hdr + body_off, body_already);
            c->body_len = body_already;
        }
        c->body[c->body_len] = 0;
        c->st = (c->body_len >= c->content_length) ? ST_DONE : ST_READ_BODY;
    } else {
        c->st = ST_DONE;
    }
    return 1;
}

static int do_read_body(client_t *c) {
    size_t need = c->content_length - c->body_len;
    if (need == 0) { c->st = ST_DONE; return 1; }
    ssize_t r = read(c->fd, c->body + c->body_len, need);
    if (r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        if (errno == EINTR) return 0;
        return -1;
    }
    if (r == 0) return -1;
    client_touch(c);
    c->body_len += (size_t)r;
    c->body[c->body_len] = 0;
    if (c->body_len >= c->content_length) c->st = ST_DONE;
    return 1;
}

static int do_write(client_t *c) {
    size_t left = c->resp_len - c->resp_off;
    if (left == 0) return 1;
    ssize_t w = write(c->fd, c->resp + c->resp_off, left);
    if (w < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        if (errno == EINTR) return 0;
        return -1;
    }
    client_touch(c);
    c->resp_off += (size_t)w;
    return c->resp_off >= c->resp_len ? 1 : 0;
}

static unsigned int client_wants(const client_t *c) {
    switch (c->st) {
        case ST_READ_HDR:
        case ST_READ_BODY:
        case ST_DONE:
            return EPOLLIN;
        case ST_WRITE_RESP:
            return EPOLLOUT;
    }
    return EPOLLIN;
}

unsigned int ipc_on_client_event(wg_ipc_t *ipc, int fd) {
    client_t *c = client_by_fd(ipc, fd);
    if (!c) return 0;

    for (;;) {
        if (c->st == ST_READ_HDR) {
            int r = do_read_hdr(c);
            if (r < 0) { client_reset(c); return 0; }
            if (r == 0) return client_wants(c);
            if (c->st == ST_READ_HDR) continue;
        }
        if (c->st == ST_READ_BODY) {
            int r = do_read_body(c);
            if (r < 0) { client_reset(c); return 0; }
            if (r == 0) return client_wants(c);
        }
        if (c->st == ST_DONE) {
            dispatch(ipc, c);
            if (c->st != ST_WRITE_RESP) { client_reset(c); return 0; }
        }
        if (c->st == ST_WRITE_RESP) {
            int r = do_write(c);
            if (r < 0) { client_reset(c); return 0; }
            if (r == 0) return client_wants(c);
            client_reset(c);
            return 0;
        }
    }
}

int ipc_sweep_timeouts(wg_ipc_t *ipc, uint64_t now_ns) {
    if (!ipc) return 0;
    int closed = 0;
    for (int i = 0; i < IPC_MAX_CLIENTS; i++) {
        client_t *c = &ipc->clients[i];
        if (c->fd < 0) continue;
        if (c->deadline_ns && now_ns >= c->deadline_ns) {
            LOG_W("ipc: client fd=%d timed out in state=%d", c->fd, c->st);
            client_reset(c);
            closed++;
        }
    }
    return closed;
}

int ipc_fd(const wg_ipc_t *ipc) { return ipc ? ipc->listen_fd : -1; }

/* -------------------- open/close -------------------- */

wg_ipc_t *ipc_open(const wg_cfg_t *cfg, wg_ipc_app_t *app) {
    wg_ipc_t *ipc = calloc(1, sizeof(*ipc));
    if (!ipc) return NULL;
    for (int i = 0; i < IPC_MAX_CLIENTS; i++) ipc->clients[i].fd = -1;
    ipc->app = app;

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) { LOG_E("socket: %s", strerror(errno)); free(ipc); return NULL; }

    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    size_t pl = strlen(cfg->sock_path);
    if (pl >= sizeof(sa.sun_path)) {
        LOG_E("sock_path too long"); close(fd); free(ipc); return NULL;
    }
    memcpy(sa.sun_path, cfg->sock_path, pl + 1);

    /* ensure parent directory exists */
    char parent[128];
    strncpy(parent, cfg->sock_path, sizeof(parent) - 1);
    parent[sizeof(parent) - 1] = 0;
    char *slash = strrchr(parent, '/');
    if (slash && slash != parent) {
        *slash = 0;
        if (mkdir_p(parent, 0755) < 0)
            LOG_W("mkdir_p(%s): %s", parent, strerror(errno));
    }
    /* Refuse to unlink anything that isn't a stale AF_UNIX socket — a
     * misconfigured sock_path pointing at /etc/shadow or a user file
     * would otherwise get wiped on every restart. */
    struct stat sst;
    if (lstat(cfg->sock_path, &sst) == 0) {
        if (S_ISSOCK(sst.st_mode)) {
            unlink(cfg->sock_path);
        } else {
            LOG_E("sock_path %s exists and is not a socket (mode=0%o); refusing to remove",
                  cfg->sock_path, sst.st_mode & 07777);
            close(fd); free(ipc); return NULL;
        }
    } else if (errno != ENOENT) {
        LOG_W("lstat(%s): %s", cfg->sock_path, strerror(errno));
    }

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        LOG_E("bind(%s): %s", cfg->sock_path, strerror(errno));
        close(fd); free(ipc); return NULL;
    }
    if (chmod(cfg->sock_path, 0660) < 0)
        LOG_W("chmod(%s, 0660): %s", cfg->sock_path, strerror(errno));
    if (cfg->sock_group[0]) {
        struct group *gr = getgrnam(cfg->sock_group);
        if (gr) {
            if (chown(cfg->sock_path, (uid_t)-1, gr->gr_gid) < 0)
                LOG_W("chown(%s, :%s): %s", cfg->sock_path,
                      cfg->sock_group, strerror(errno));
        } else {
            LOG_W("sock_group %s does not exist — leaving socket as root:root",
                  cfg->sock_group);
        }
    }
    if (listen(fd, 8) < 0) {
        LOG_E("listen: %s", strerror(errno));
        close(fd); free(ipc); return NULL;
    }
    ipc->listen_fd = fd;
    LOG_I("ipc: listening on %s", cfg->sock_path);
    return ipc;
}

void ipc_close(wg_ipc_t *ipc) {
    if (!ipc) return;
    for (int i = 0; i < IPC_MAX_CLIENTS; i++)
        if (ipc->clients[i].fd >= 0) client_reset(&ipc->clients[i]);
    if (ipc->listen_fd >= 0) close(ipc->listen_fd);
    free(ipc);
}
