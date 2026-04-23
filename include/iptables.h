#ifndef WGATECTL_IPTABLES_H
#define WGATECTL_IPTABLES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    char     iptables_bin[96];
} wg_iptables_t;

/* Describes the desired FORWARD DROP state: which LAN IPs should be
 * blocked right now. Callers build this list from schedule + DHCP-range
 * batch controls before each reconcile. */
typedef struct {
    uint32_t *blocked_ips;   /* host-order */
    size_t    n;
    size_t    cap;
} wg_block_set_t;

void wg_block_set_init(wg_block_set_t *b);
void wg_block_set_free(wg_block_set_t *b);
void wg_block_set_add (wg_block_set_t *b, uint32_t ip);
bool wg_block_set_has (const wg_block_set_t *b, uint32_t ip);

/* One-time bootstrap: ensure the two ipset ACCEPT rules sit at FORWARD
 * slots 1 and 2. Idempotent. */
int iptables_bootstrap(wg_iptables_t *t, const char *ipset_bin_for_match);

/* Reconcile FORWARD DROP rules so they match `desired`:
 *   - add missing DROPs
 *   - remove stale DROPs inside `net_addr/net_mask` that aren't desired
 *   - reinsert the ipset ACCEPT rules at slots 1-2 if missing.
 * `added` / `removed` counts are filled (NULL to skip). */
int iptables_reconcile(wg_iptables_t *t,
                       uint32_t net_addr, uint32_t net_mask,
                       const wg_block_set_t *desired,
                       int *added, int *removed);

/* Add or remove a single DROP rule directly (used by /dhcp-range
 * endpoints for immediate feedback — reconcile still catches any drift). */
int iptables_drop_add   (wg_iptables_t *t, uint32_t ip);
int iptables_drop_remove(wg_iptables_t *t, uint32_t ip);

#endif
