#include "blocks.h"
#include "json.h"
#include "log.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>

void blocks_init(wg_blocks_t *b, const char *path) {
    memset(b, 0, sizeof(*b));
    if (path) {
        strncpy(b->path, path, sizeof(b->path) - 1);
        b->path[sizeof(b->path) - 1] = 0;
    }
}

void blocks_free(wg_blocks_t *b) {
    if (!b) return;
    for (size_t i = 0; i < b->n; i++) free(b->keys[i]);
    free(b->keys);
    memset(b, 0, sizeof(*b));
}

void blocks_canonicalise(const wg_leases_t *leases, const char *key,
                         char *out, size_t cap) {
    uint32_t ip;
    if (ip_parse(key, &ip)) {
        /* IP → always dotted-quad form */
        char ipbuf[16];
        ip_format(ip, ipbuf);
        strncpy(out, ipbuf, cap - 1);
        out[cap - 1] = 0;
        return;
    }
    const wg_lease_t *l = leases ? leases_by_name(leases, key) : NULL;
    if (l && l->name[0]) {
        strncpy(out, l->name, cap - 1);
        out[cap - 1] = 0;
        return;
    }
    strncpy(out, key, cap - 1);
    out[cap - 1] = 0;
}

bool blocks_contains(const wg_blocks_t *b, const wg_leases_t *leases,
                     const char *key) {
    char canon[64];
    blocks_canonicalise(leases, key, canon, sizeof(canon));
    for (size_t i = 0; i < b->n; i++) {
        char k[64];
        blocks_canonicalise(leases, b->keys[i], k, sizeof(k));
        if (strcmp(k, canon) == 0) return true;
    }
    return false;
}

bool blocks_resolve_ip(const wg_leases_t *leases, const char *key,
                       uint32_t *out) {
    uint32_t ip;
    if (ip_parse(key, &ip)) { *out = ip; return true; }
    const wg_lease_t *l = leases ? leases_by_name(leases, key) : NULL;
    if (!l) return false;
    *out = l->ip;
    return true;
}

bool blocks_contains_ip(const wg_blocks_t *b, const wg_leases_t *leases,
                        uint32_t ip) {
    for (size_t i = 0; i < b->n; i++) {
        uint32_t kip;
        if (blocks_resolve_ip(leases, b->keys[i], &kip) && kip == ip)
            return true;
    }
    return false;
}

int blocks_add(wg_blocks_t *b, const wg_leases_t *leases, const char *key) {
    char canon[64];
    blocks_canonicalise(leases, key, canon, sizeof(canon));
    /* already present? */
    for (size_t i = 0; i < b->n; i++) {
        char k[64];
        blocks_canonicalise(leases, b->keys[i], k, sizeof(k));
        if (strcmp(k, canon) == 0) return 0;
    }
    if (b->n == b->cap) {
        size_t ncap = b->cap ? b->cap * 2 : 16;
        char **nk = realloc(b->keys, ncap * sizeof(*nk));
        if (!nk) return 0;
        b->keys = nk;
        b->cap  = ncap;
    }
    b->keys[b->n] = xstrdup(canon);
    if (!b->keys[b->n]) return 0;
    b->n++;
    return 1;
}

int blocks_remove(wg_blocks_t *b, const wg_leases_t *leases, const char *key) {
    char canon[64];
    blocks_canonicalise(leases, key, canon, sizeof(canon));
    for (size_t i = 0; i < b->n; i++) {
        char k[64];
        blocks_canonicalise(leases, b->keys[i], k, sizeof(k));
        if (strcmp(k, canon) == 0) {
            free(b->keys[i]);
            memmove(&b->keys[i], &b->keys[i + 1],
                    (b->n - i - 1) * sizeof(*b->keys));
            b->n--;
            return 1;
        }
    }
    return 0;
}

int blocks_load(wg_blocks_t *b) {
    if (!b->path[0]) return 0;
    size_t n = 0;
    char *buf = read_small_file(b->path, 128 * 1024, &n);
    if (!buf) return 0;
    const char *err = NULL;
    json_val_t *v = json_parse(buf, n, &err);
    free(buf);
    if (!v) { LOG_W("blocks: parse %s: %s", b->path, err ? err : "?"); return -1; }
    if (v->type != JV_ARR) { json_val_free(v); return -1; }
    for (size_t i = 0; i < v->u.arr.n; i++) {
        const json_val_t *iv = &v->u.arr.items[i];
        if (iv->type != JV_STR) continue;
        if (b->n == b->cap) {
            size_t ncap = b->cap ? b->cap * 2 : 16;
            char **nk = realloc(b->keys, ncap * sizeof(*nk));
            if (!nk) break;
            b->keys = nk;
            b->cap  = ncap;
        }
        b->keys[b->n] = xstrdup(iv->u.str.s);
        if (b->keys[b->n]) b->n++;
    }
    json_val_free(v);
    LOG_I("blocks: loaded %zu entr%s from %s",
          b->n, b->n == 1 ? "y" : "ies", b->path);
    return 0;
}

int blocks_save(const wg_blocks_t *b) {
    if (!b->path[0]) return 0;
    json_out_t j;
    json_out_init(&j);
    json_arr_begin(&j);
    for (size_t i = 0; i < b->n; i++) json_str(&j, b->keys[i]);
    json_arr_end(&j);
    int rc = atomic_write(b->path, j.buf ? j.buf : "[]",
                          j.buf ? j.len : 2);
    json_out_free(&j);
    return rc;
}
