#include "blocks.h"
#include "json.h"
#include "log.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>   /* ssize_t */

/* Cap the persisted block set to keep an API flood from blowing up
 * memory and serialising into a 100MB JSON. */
#define BLOCKS_MAX 2048

void blocks_init(wg_blocks_t *b, const char *path) {
    memset(b, 0, sizeof(*b));
    if (path) {
        strncpy(b->path, path, sizeof(b->path) - 1);
        b->path[sizeof(b->path) - 1] = 0;
    }
}

static void item_free(wg_block_item_t *it) {
    free(it->key);
    free(it->reason);
    it->key = NULL;
    it->reason = NULL;
    it->added_at = 0;
}

void blocks_free(wg_blocks_t *b) {
    if (!b) return;
    for (size_t i = 0; i < b->n; i++) item_free(&b->items[i]);
    free(b->items);
    memset(b, 0, sizeof(*b));
}

void blocks_clear(wg_blocks_t *b) {
    if (!b) return;
    for (size_t i = 0; i < b->n; i++) item_free(&b->items[i]);
    b->n = 0;
}

void blocks_canonicalise(const wg_leases_t *leases, const char *key,
                         char *out, size_t cap) {
    uint32_t ip;
    if (ip_parse(key, &ip)) {
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

static ssize_t find_idx(const wg_blocks_t *b, const wg_leases_t *leases,
                        const char *canon) {
    for (size_t i = 0; i < b->n; i++) {
        char k[64];
        blocks_canonicalise(leases, b->items[i].key, k, sizeof(k));
        if (strcmp(k, canon) == 0) return (ssize_t)i;
    }
    return -1;
}

bool blocks_contains(const wg_blocks_t *b, const wg_leases_t *leases,
                     const char *key) {
    char canon[64];
    blocks_canonicalise(leases, key, canon, sizeof(canon));
    return find_idx(b, leases, canon) >= 0;
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
        if (blocks_resolve_ip(leases, b->items[i].key, &kip) && kip == ip)
            return true;
    }
    return false;
}

const char *blocks_reason(const wg_blocks_t *b, const wg_leases_t *leases,
                          const char *key) {
    const wg_block_item_t *it = blocks_find(b, leases, key);
    return it ? it->reason : NULL;
}

const wg_block_item_t *blocks_find(const wg_blocks_t *b,
                                   const wg_leases_t *leases,
                                   const char *key) {
    char canon[64];
    blocks_canonicalise(leases, key, canon, sizeof(canon));
    ssize_t idx = find_idx(b, leases, canon);
    if (idx < 0) return NULL;
    return &b->items[idx];
}

const wg_block_item_t *blocks_find_by_ip(const wg_blocks_t *b,
                                         const wg_leases_t *leases,
                                         uint32_t ip) {
    for (size_t i = 0; i < b->n; i++) {
        uint32_t kip;
        if (blocks_resolve_ip(leases, b->items[i].key, &kip) && kip == ip)
            return &b->items[i];
    }
    return NULL;
}

static int grow_items(wg_blocks_t *b) {
    if (b->n < b->cap) return 0;
    if (b->cap >= BLOCKS_MAX) return -1;
    size_t ncap = b->cap ? b->cap * 2 : 16;
    if (ncap > BLOCKS_MAX) ncap = BLOCKS_MAX;
    wg_block_item_t *ni = realloc(b->items, ncap * sizeof(*ni));
    if (!ni) return -1;
    /* zero new tail so owned pointers start NULL */
    memset(ni + b->cap, 0, (ncap - b->cap) * sizeof(*ni));
    b->items = ni;
    b->cap   = ncap;
    return 0;
}

int blocks_add(wg_blocks_t *b, const wg_leases_t *leases, const char *key,
               const char *reason, int64_t added_at) {
    if (!key || !*key) return 0;
    char canon[64];
    blocks_canonicalise(leases, key, canon, sizeof(canon));
    if (!canon[0]) return 0;
    if (find_idx(b, leases, canon) >= 0) return 0;
    if (b->n >= BLOCKS_MAX) {
        LOG_W("blocks: at cap (%d); refusing to add %s", BLOCKS_MAX, canon);
        return 0;
    }
    if (grow_items(b) < 0) return 0;
    wg_block_item_t *it = &b->items[b->n];
    it->key      = xstrdup(canon);
    if (!it->key) return 0;
    it->reason   = (reason && *reason) ? xstrdup(reason) : NULL;
    it->added_at = added_at;
    b->n++;
    return 1;
}

int blocks_remove(wg_blocks_t *b, const wg_leases_t *leases, const char *key) {
    char canon[64];
    blocks_canonicalise(leases, key, canon, sizeof(canon));
    ssize_t idx = find_idx(b, leases, canon);
    if (idx < 0) return 0;
    item_free(&b->items[idx]);
    memmove(&b->items[idx], &b->items[idx + 1],
            (b->n - (size_t)idx - 1) * sizeof(*b->items));
    b->n--;
    /* zero the now-vacant tail slot */
    memset(&b->items[b->n], 0, sizeof(b->items[b->n]));
    return 1;
}

/* ---------------------------- persistence --------------------------- */

/* Append one item with (key, reason, added_at). Caller pre-canonicalises.
 * Returns 0 on success. */
static int append_raw(wg_blocks_t *b, const char *canon,
                      const char *reason, int64_t added_at) {
    if (!canon || !*canon) return 0;
    if (b->n >= BLOCKS_MAX) return 0;
    if (grow_items(b) < 0) return -1;
    wg_block_item_t *it = &b->items[b->n];
    it->key      = xstrdup(canon);
    if (!it->key) return -1;
    it->reason   = (reason && *reason) ? xstrdup(reason) : NULL;
    it->added_at = added_at;
    b->n++;
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

    int truncated = 0;
    for (size_t i = 0; i < v->u.arr.n; i++) {
        const json_val_t *iv = &v->u.arr.items[i];
        if (b->n >= BLOCKS_MAX) { truncated = 1; break; }

        if (iv->type == JV_STR) {
            /* legacy format: plain key string, no reason/timestamp */
            append_raw(b, iv->u.str.s, NULL, 0);
        } else if (iv->type == JV_OBJ) {
            const char *key = NULL, *reason = NULL;
            int64_t added_at = 0;
            json_get_str(json_obj_get(iv, "key"),      &key);
            json_get_str(json_obj_get(iv, "reason"),   &reason);
            json_get_i64(json_obj_get(iv, "added_at"), &added_at);
            if (!key) continue;
            append_raw(b, key, reason, added_at);
        }
    }
    json_val_free(v);
    if (truncated)
        LOG_W("blocks: truncating on-disk list at %d entries", BLOCKS_MAX);
    LOG_I("blocks: loaded %zu entr%s from %s",
          b->n, b->n == 1 ? "y" : "ies", b->path);
    return 0;
}

int blocks_save(const wg_blocks_t *b) {
    if (!b->path[0]) return 0;
    json_out_t j;
    json_out_init(&j);
    json_arr_begin(&j);
    for (size_t i = 0; i < b->n; i++) {
        const wg_block_item_t *it = &b->items[i];
        json_obj_begin(&j);
        json_kstr(&j, "key", it->key);
        if (it->reason && *it->reason) json_kstr(&j, "reason", it->reason);
        if (it->added_at)              json_ki64(&j, "added_at", it->added_at);
        json_obj_end(&j);
    }
    json_arr_end(&j);
    int rc = atomic_write(b->path, j.buf ? j.buf : "[]",
                          j.buf ? j.len : 2);
    json_out_free(&j);
    return rc;
}
