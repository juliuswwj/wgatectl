#include "ipc.h"
#include "json.h"
#include "log.h"
#include "metrics.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#define IPC_MAX_CLIENTS 16
#define IPC_HDR_CAP     8192
#define IPC_BODY_CAP    (64 * 1024)

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
            if (v1 >= 0 && v2 >= 0) { *w++ = (char)((v1 << 4) | v2); r += 3; continue; }
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

static void rebuild_blockset(const wg_ipc_app_t *app, wg_block_set_t *out) {
    wg_block_set_init(out);
    const wg_blocks_t *b = app->blocks;
    for (size_t i = 0; i < b->n; i++) {
        uint32_t ip;
        if (!blocks_resolve_ip(app->leases, b->keys[i], &ip)) continue;
        if (!ip_in_subnet(ip, app->cfg->net_addr, app->cfg->net_mask)) continue;
        wg_block_set_add(out, ip);
    }
}

static void reconcile_after_change(wg_ipc_app_t *app) {
    wg_block_set_t b;
    rebuild_blockset(app, &b);
    iptables_reconcile(app->ipt, app->cfg->net_addr, app->cfg->net_mask,
                       &b, NULL, NULL);
    wg_block_set_free(&b);
    blocks_save(app->blocks);
}

/* -------------------- handlers -------------------- */

static void handle_status(wg_ipc_t *ipc, client_t *c) {
    json_out_t j;
    json_out_init(&j);
    json_obj_begin(&j);
    json_kbool(&j, "ok", true);
    uint64_t up_s = (now_mono_ns() - ipc->app->started_mono_ns) / 1000000000ull;
    json_ku64(&j, "uptime_s", up_s);
    json_ki64(&j, "blocked_count", (int)ipc->app->blocks->n);
    json_ki64(&j, "lease_count",   (int)ipc->app->leases->n);
    json_kstr(&j, "iface",   ipc->app->cfg->iface);
    json_kstr(&j, "network", ipc->app->cfg->network_cidr);
    json_obj_end(&j);
    respond_json(c, 200, &j);
    json_out_free(&j);
}

static void handle_hosts(wg_ipc_t *ipc, client_t *c) {
    const wg_leases_t *leases = ipc->app->leases;
    const wg_blocks_t *blocks = ipc->app->blocks;

    json_out_t j;
    json_out_init(&j);
    json_arr_begin(&j);

    for (size_t i = 0; i < leases->n; i++) {
        const wg_lease_t *l = &leases->items[i];
        char ipbuf[16], macbuf[18];
        ip_format(l->ip, ipbuf);
        mac_format(l->mac, macbuf);
        json_obj_begin(&j);
        if (l->name[0]) json_kstr(&j, "name", l->name);
        else            json_knull(&j, "name");
        json_kstr (&j, "ip",  ipbuf);
        json_kstr (&j, "mac", macbuf);
        json_kbool(&j, "is_static", l->is_static);
        json_kbool(&j, "blocked", blocks_contains_ip(blocks, leases, l->ip));
        json_obj_end(&j);
    }
    /* also surface any blocked keys that don't correspond to a lease
     * (e.g. a raw IP that the agent blocked for a phantom device) */
    for (size_t i = 0; i < blocks->n; i++) {
        uint32_t ip;
        bool have_ip = blocks_resolve_ip(leases, blocks->keys[i], &ip);
        if (have_ip && leases_by_ip(leases, ip)) continue;
        if (!have_ip && leases_by_name(leases, blocks->keys[i])) continue;
        json_obj_begin(&j);
        json_kstr (&j, "name", blocks->keys[i]);
        if (have_ip) {
            char ipbuf[16];
            ip_format(ip, ipbuf);
            json_kstr(&j, "ip", ipbuf);
        }
        json_kbool(&j, "blocked", true);
        json_obj_end(&j);
    }
    json_arr_end(&j);
    respond_json(c, 200, &j);
    json_out_free(&j);
}

/* Extract "/hosts/<key>/<action>" → key, action. Returns action pointer. */
static const char *path_after_key(char *path, const char *prefix,
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

static void handle_host_action(wg_ipc_t *ipc, client_t *c,
                               const char *key, const char *action) {
    wg_ipc_app_t *app = ipc->app;
    bool want_block = (strcmp(action, "block") == 0);
    bool want_allow = (strcmp(action, "allow") == 0);
    if (!want_block && !want_allow) {
        respond_simple(c, 404, "unknown action");
        return;
    }

    int changed = want_block
        ? blocks_add   (app->blocks, app->leases, key)
        : blocks_remove(app->blocks, app->leases, key);

    if (changed) {
        reconcile_after_change(app);
        char ipbuf[16] = "";
        uint32_t ip;
        if (blocks_resolve_ip(app->leases, key, &ip)) ip_format(ip, ipbuf);
        metrics_emit_control(app->jl, now_wall_s(),
                             key, ipbuf[0] ? ipbuf : NULL,
                             want_block ? "block" : "allow", "api");
    }
    json_out_t j; json_out_init(&j);
    json_obj_begin(&j);
    json_kbool(&j, "ok", true);
    json_kstr (&j, "host", key);
    json_kbool(&j, "blocked", want_block);
    json_kbool(&j, "changed", changed != 0);
    json_obj_end(&j);
    respond_json(c, 200, &j);
    json_out_free(&j);
}

static void handle_dhcp_range(wg_ipc_t *ipc, client_t *c, bool block) {
    wg_ipc_app_t *app = ipc->app;
    uint32_t lo, hi;
    if (!leases_dhcp_range(app->leases, &lo, &hi)) {
        respond_simple(c, 404, "no dhcp-range in dnsmasq.conf");
        return;
    }
    int n_affected = 0;
    json_out_t aff; json_out_init(&aff);
    json_arr_begin(&aff);
    for (uint32_t ip = lo; ip <= hi; ip++) {
        const wg_lease_t *l = leases_by_ip(app->leases, ip);
        if (l && l->is_static) continue;
        char ipbuf[16];
        ip_format(ip, ipbuf);
        int changed = block
            ? blocks_add   (app->blocks, app->leases, ipbuf)
            : blocks_remove(app->blocks, app->leases, ipbuf);
        if (changed) {
            json_str(&aff, ipbuf);
            n_affected++;
        }
    }
    json_arr_end(&aff);
    if (n_affected > 0) {
        reconcile_after_change(app);
        metrics_emit_control(app->jl, now_wall_s(),
                             "dhcp-range", NULL,
                             block ? "block" : "allow", "api");
    }

    json_out_t j; json_out_init(&j);
    json_obj_begin(&j);
    json_kbool(&j, "ok", true);
    json_ki64 (&j, "affected_count", n_affected);
    json_key  (&j, "affected");
    json_raw  (&j, aff.buf ? aff.buf : "[]");
    json_obj_end(&j);
    respond_json(c, 200, &j);
    json_out_free(&j);
    json_out_free(&aff);
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
    leases_reload(app->leases, app->cfg->dnsmasq_conf, app->cfg->dnsmasq_leases);
    reconcile_after_change(app);
    respond_simple(c, 200, NULL);
}

/* -------------------- route dispatch -------------------- */

static void dispatch(wg_ipc_t *ipc, client_t *c) {
    char keybuf[128];
    const char *action;

    if (strcmp(c->method, "GET") == 0 && strcmp(c->path, "/status") == 0) {
        handle_status(ipc, c); return;
    }
    if (strcmp(c->method, "GET") == 0 && strcmp(c->path, "/hosts") == 0) {
        handle_hosts(ipc, c); return;
    }
    if (strcmp(c->method, "POST") == 0 &&
        (action = path_after_key(c->path, "/hosts/", keybuf, sizeof(keybuf))) != NULL) {
        handle_host_action(ipc, c, keybuf, action); return;
    }
    if (strcmp(c->method, "POST") == 0 && strcmp(c->path, "/dhcp-range/allow") == 0) {
        handle_dhcp_range(ipc, c, false); return;
    }
    if (strcmp(c->method, "POST") == 0 && strcmp(c->path, "/dhcp-range/block") == 0) {
        handle_dhcp_range(ipc, c, true); return;
    }
    if (strcmp(c->method, "GET") == 0 && strcmp(c->path, "/metrics/tail") == 0) {
        handle_metrics_tail(ipc, c); return;
    }
    if (strcmp(c->method, "POST") == 0 && strcmp(c->path, "/reload") == 0) {
        handle_reload(ipc, c); return;
    }
    respond_simple(c, 404, "no such route");
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
    c->resp_off += (size_t)w;
    return c->resp_off >= c->resp_len ? 1 : 0;
}

int ipc_on_client_event(wg_ipc_t *ipc, int fd) {
    client_t *c = client_by_fd(ipc, fd);
    if (!c) return -1;

    for (;;) {
        if (c->st == ST_READ_HDR) {
            int r = do_read_hdr(c);
            if (r < 0) { client_reset(c); return 0; }
            if (r == 0) return 0;
            if (c->st == ST_READ_HDR) continue;
        }
        if (c->st == ST_READ_BODY) {
            int r = do_read_body(c);
            if (r < 0) { client_reset(c); return 0; }
            if (r == 0) return 0;
        }
        if (c->st == ST_DONE) {
            dispatch(ipc, c);
            if (c->st != ST_WRITE_RESP) { client_reset(c); return 0; }
        }
        if (c->st == ST_WRITE_RESP) {
            int r = do_write(c);
            if (r < 0) { client_reset(c); return 0; }
            if (r == 0) return 0;
            client_reset(c);
            return 0;
        }
    }
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
    unlink(cfg->sock_path);

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
