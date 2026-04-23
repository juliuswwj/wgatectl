#ifndef WGATECTL_ARP_BIND_H
#define WGATECTL_ARP_BIND_H

#include "leases.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Proactive ARP binding for the static-assignment zone.
 *
 * Every IP in `static_cidr` (minus network/broadcast) gets a permanent
 * ARP entry on the LAN interface:
 *   - if dnsmasq.conf has a matching dhcp-host=MAC,IP line, use that MAC
 *   - otherwise use a DUMMY locally-administered MAC so the slot black-holes.
 *
 * dhcp-host entries whose IP falls OUTSIDE the static CIDR are pinned too,
 * so spoofing a static IP on the wire is never possible.
 *
 * All pins survive until shutdown or rebind.  Uses `ip neigh replace …
 * nud permanent`.
 */

typedef struct wg_arp_bind {
    char      ip_bin [96];
    char      iface  [32];
    bool      active;           /* false when static_cidr is empty/unparseable */
    uint32_t  cidr_addr;        /* host-order */
    uint32_t  cidr_mask;

    uint32_t *bound_ips;        /* IPs currently pinned, in host order */
    size_t    n_bound, cap_bound;
} wg_arp_bind_t;

/* Initialise. Returns 0 on success, -1 if static_cidr is set but parse
 * fails. If static_cidr is empty or NULL, `ab->active = false` and all
 * subsequent operations are no-ops. */
int  arp_bind_init    (wg_arp_bind_t *ab,
                       const char *ip_bin,
                       const char *iface,
                       const char *static_cidr);

/* Re-apply bindings based on the current leases snapshot. Entries that
 * were bound before but don't belong this time are removed; the rest
 * (including real-MAC entries whose dnsmasq-host line may have changed)
 * are replaced with the current value. Called at startup, on SIGHUP,
 * and after POST /reload. */
void arp_bind_apply   (wg_arp_bind_t *ab, const wg_leases_t *leases);

/* Remove every ARP entry we've installed. Called from shutdown_all. */
void arp_bind_shutdown(wg_arp_bind_t *ab);

void arp_bind_free    (wg_arp_bind_t *ab);

#endif
