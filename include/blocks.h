#ifndef WGATECTL_BLOCKS_H
#define WGATECTL_BLOCKS_H

#include "leases.h"

#include <stdbool.h>
#include <stdint.h>

/* Flat set of blocked keys. A "key" is whatever string the agent (or CLI)
 * passed to the block API — either an IP in dotted-quad form, or a host
 * name that the dnsmasq config knows about. We store both verbatim so
 * that leases can come and go without the block list self-corrupting.
 *
 * Blocks are NOT permanent: at the next mode transition into supervised
 * or open the whole list is cleared by main's do_minute_flush. The
 * `added_at` timestamp and optional `reason` are kept for audit. */

typedef struct {
    char    *key;         /* canonicalised, owned */
    char    *reason;      /* nullable, owned */
    int64_t  added_at;    /* wall-clock epoch when added; 0 if unknown */
} wg_block_item_t;

typedef struct {
    wg_block_item_t *items;
    size_t           n;
    size_t           cap;
    char             path[256];
} wg_blocks_t;

void blocks_init(wg_blocks_t *b, const char *path);
void blocks_free(wg_blocks_t *b);

/* Load/save JSON. load accepts both legacy array-of-strings and the
 * current array-of-objects form. save always writes objects. Missing
 * file on load is fine (empty set). */
int  blocks_load(wg_blocks_t *b);
int  blocks_save(const wg_blocks_t *b);

/* Normalise a key: if it parses as an IP, return the canonical dotted
 * quad; if it's a known host name, return the name. Otherwise return it
 * verbatim. Result is copied into `out` (cap bytes). */
void blocks_canonicalise(const wg_leases_t *leases, const char *key,
                         char *out, size_t cap);

/* Returns true if the canonical form of `key` is currently in the set. */
bool blocks_contains(const wg_blocks_t *b, const wg_leases_t *leases,
                     const char *key);

/* Returns true if the LAN IP is currently blocked (either by IP-key or by
 * a name-key that resolves to this IP). */
bool blocks_contains_ip(const wg_blocks_t *b, const wg_leases_t *leases,
                        uint32_t ip);

/* Returns: 1 if added, 0 if already present / rejected. `reason` and
 * `added_at` may be NULL/0. */
int  blocks_add(wg_blocks_t *b, const wg_leases_t *leases, const char *key,
                const char *reason, int64_t added_at);

/* Returns: 1 if removed, 0 if not present. */
int  blocks_remove(wg_blocks_t *b, const wg_leases_t *leases, const char *key);

/* Drop every entry; zeroes n. Cap/items buffer kept for reuse. */
void blocks_clear(wg_blocks_t *b);

/* Resolve a block-list key to a LAN IP (host-order). Returns true on
 * success. */
bool blocks_resolve_ip(const wg_leases_t *leases, const char *key,
                       uint32_t *out);

/* Return the stored reason for a block key (canonicalised at lookup),
 * or NULL if the key isn't blocked / has no reason. Pointer is owned
 * by the blocks structure; do not free. */
const char *blocks_reason(const wg_blocks_t *b, const wg_leases_t *leases,
                          const char *key);

/* Return the full item for a block key, or NULL if not present. Same
 * ownership rules as blocks_reason. */
const wg_block_item_t *blocks_find(const wg_blocks_t *b,
                                   const wg_leases_t *leases,
                                   const char *key);

/* Return the item whose key resolves to `ip`, or NULL. */
const wg_block_item_t *blocks_find_by_ip(const wg_blocks_t *b,
                                         const wg_leases_t *leases,
                                         uint32_t ip);

#endif
