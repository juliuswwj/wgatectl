#ifndef WGATECTL_IPTABLES_H
#define WGATECTL_IPTABLES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    char     iptables_bin[96];
    /* Signature of the last successfully-applied desired state. When the
     * next reconcile call computes the same signature, the whole
     * delete-and-re-append pass is skipped — there is nothing to do, and
     * the +0 -0 log lines were burying the lines that matter (real
     * changes). 0 + have_last_sig=false means "never applied". */
    uint64_t last_sig;
    bool     have_last_sig;
} wg_iptables_t;

/* Reconcile the tail of the FORWARD chain so it matches wgatectl's
 * desired state.
 *
 *   After external DOCKER-* and -i <wan> rules (which we never touch),
 *   append a contiguous block of rules in this order — every one tagged
 *   with `-m comment --comment wgatectl`:
 *
 *     1. -i <lan> -m set --match-set wgate_allow      dst -j ACCEPT
 *     2. -s <static_cidr> -j ACCEPT                                       (if static_cidr)
 *     3. -i <lan> -m set --match-set wgate_pin_open   src -j ACCEPT       (per-host pin → open)
 *     4. -i <lan> -m set --match-set wgate_pin_closed src -j DROP         (per-host pin → closed)
 *     5. -i <lan> -m set --match-set wgate_pin_filt   src \
 *                 -m set --match-set wgate_filterd    dst -j DROP         (pin → filtered, drop matched)
 *     6. -i <lan> -m set --match-set wgate_pin_filt   src -j ACCEPT       (pin → filtered, allow rest)
 *     7. global mode:
 *          closed   → -i <lan> -j DROP
 *          filtered → -i <lan> -m set --match-set wgate_filterd dst -j DROP
 *          open     → (no rule)
 *
 *   No trailing catch-all ACCEPT: FORWARD's default policy is ACCEPT, so
 *   anything that survives our block is already permitted; appending
 *   one would mask admin-added DROPs below.
 *
 *   The FORWARD chain emission is stateless (no -m state ESTABLISHED,RELATED).
 *   In-flight TCP fails through retransmission/RST when a pin or global
 *   mode flips — accepted behaviour.
 *
 *   Any previously-installed wgatectl rule (including legacy per-IP
 *   DROPs in the LAN subnet from removed predecessors) is removed
 *   before the fresh block is appended.
 *
 * `closed_mode` and `filtered_mode` are mutually exclusive (both false
 * means "open"). They drive rule 7. Returns 0 on success, -1 on
 * fatal error (e.g. iptables binary unusable). */
int iptables_reconcile(wg_iptables_t *t,
                       const char *lan_iface,
                       const char *static_cidr,
                       uint32_t net_addr, uint32_t net_mask,
                       bool closed_mode,
                       bool filtered_mode);

#endif
