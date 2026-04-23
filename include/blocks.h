#ifndef WGATECTL_BLOCKS_H
#define WGATECTL_BLOCKS_H

#include "leases.h"

#include <stdbool.h>
#include <stdint.h>

/* Flat set of blocked keys. A "key" is whatever string the agent (or CLI)
 * passed to the block API — either an IP in dotted-quad form, or a host
 * name that the dnsmasq config knows about. We store both verbatim so
 * that leases can come and go without the block list self-corrupting. */

typedef struct {
    char    **keys;       /* NUL-terminated, owned */
    size_t    n;
    size_t    cap;
    char      path[256];  /* persistence file */
} wg_blocks_t;

void blocks_init(wg_blocks_t *b, const char *path);
void blocks_free(wg_blocks_t *b);

/* Load/save JSON array-of-strings. Missing file is fine (empty set). */
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

/* Returns: 1 if added, 0 if already present. */
int  blocks_add   (wg_blocks_t *b, const wg_leases_t *leases, const char *key);

/* Returns: 1 if removed, 0 if not present. */
int  blocks_remove(wg_blocks_t *b, const wg_leases_t *leases, const char *key);

/* Resolve a block-list key to a LAN IP (host-order). Returns true on
 * success. */
bool blocks_resolve_ip(const wg_leases_t *leases, const char *key,
                       uint32_t *out);

#endif
