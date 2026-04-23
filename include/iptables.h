#ifndef WGATECTL_IPTABLES_H
#define WGATECTL_IPTABLES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    char     iptables_bin[96];
} wg_iptables_t;

/* The set of LAN IPs that should be per-host DROPped (permanent blocks
 * from blocks.json plus any supervisor-triggered device minus any active
 * grants). Closed-mode dhcp-range blocking is NOT enumerated here — a
 * single `-i <lan> -j DROP` rule covers that. */
typedef struct {
    uint32_t *blocked_ips;   /* host-order */
    size_t    n;
    size_t    cap;
} wg_block_set_t;

void wg_block_set_init(wg_block_set_t *b);
void wg_block_set_free(wg_block_set_t *b);
void wg_block_set_add (wg_block_set_t *b, uint32_t ip);
bool wg_block_set_has (const wg_block_set_t *b, uint32_t ip);

/* Reconcile the tail of the FORWARD chain so it matches wgatectl's
 * desired state.
 *
 *   After external DOCKER-* and -i <wan> rules (which we never touch),
 *   append a contiguous block of rules in this order — every one tagged
 *   with `-m comment --comment wgatectl`:
 *
 *     1. -i <lan> -m set --match-set wgate_allow dst -j ACCEPT
 *     2. -i <lan> -m set --match-set wgate_allow src -j ACCEPT
 *     3. -s <static_cidr> -j ACCEPT                   (if static_cidr != NULL/"")
 *     4. -s <ip>/32 -j DROP  (for each ip in `desired_drops`, sorted)
 *     5. -i <lan> -j DROP                             (if closed_mode)
 *
 *   No trailing catch-all ACCEPT: FORWARD's default policy is ACCEPT,
 *   so anything that survives our block is already permitted; adding
 *   an explicit ACCEPT would mask admin-added DROPs below.
 *
 *   Any previously-installed wgatectl rule (or legacy rule from before
 *   the comment tag existed) is removed before the fresh block is
 *   appended.
 *
 * `added` / `removed` receive the number of append / delete actions
 * that succeeded (pass NULL to skip). Returns 0 on success, -1 on
 * fatal error (e.g. iptables binary unusable). */
int iptables_reconcile(wg_iptables_t *t,
                       const char *lan_iface,
                       const char *static_cidr,
                       uint32_t net_addr, uint32_t net_mask,
                       const wg_block_set_t *desired_drops,
                       bool closed_mode,
                       int *added, int *removed);

#endif
