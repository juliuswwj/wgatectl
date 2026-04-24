#ifndef WGATECTL_LEASES_H
#define WGATECTL_LEASES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t ip;        /* host-order */
    uint8_t  mac[6];
    char     name[64];
    bool     is_static; /* true iff IP lies inside WG_STATIC_CIDR */
} wg_lease_t;

typedef struct {
    wg_lease_t *items;
    size_t      n;
    size_t      cap;
    uint32_t    dhcp_lo;      /* host-order, 0 if unset */
    uint32_t    dhcp_hi;
} wg_leases_t;

void leases_init(wg_leases_t *t);
void leases_free(wg_leases_t *t);

/* Reload from paths. Missing files are tolerated (empty result + warn).
 * `static_cidr` (may be NULL/"") gates which entries are flagged is_static:
 * an entry's is_static is set iff its IP lies inside the CIDR. */
void leases_reload(wg_leases_t *t,
                   const char  *dnsmasq_conf,
                   const char  *dnsmasq_leases,
                   const char  *static_cidr);

const wg_lease_t *leases_by_ip  (const wg_leases_t *t, uint32_t ip);
const wg_lease_t *leases_by_name(const wg_leases_t *t, const char *name);

/* Returns true if a dhcp-range was found. */
bool leases_dhcp_range(const wg_leases_t *t, uint32_t *lo, uint32_t *hi);

#endif
