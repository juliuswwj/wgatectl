#ifndef WGATECTL_LEASES_H
#define WGATECTL_LEASES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Forward decl — leases.c keeps a pointer to the seen-db so it can fill
 * first_seen/last_seen on each reload without the caller having to. */
typedef struct wg_seen_db wg_seen_db_t;

typedef struct {
    uint32_t ip;          /* host-order */
    uint8_t  mac[6];
    char     name[64];
    bool     is_static;   /* true iff IP lies inside WG_STATIC_CIDR */

    /* Whether this entry was present in dnsmasq.leases at the most
     * recent reload. Static dhcp-host entries that aren't currently
     * leased have this false. Used by the diff to derive add/remove
     * lease events. */
    bool     in_lease_file;

    /* Wall-clock seconds. 0 means "unknown" (no MAC, or never seen
     * since the seen-db was created). first_seen is persistent across
     * daemon restarts; last_seen is bumped each time the MAC reappears
     * in the dnsmasq.leases file. */
    int64_t  first_seen;
    int64_t  last_seen;
} wg_lease_t;

typedef struct {
    wg_lease_t *items;
    size_t      n;
    size_t      cap;
    uint32_t    dhcp_lo;      /* host-order, 0 if unset */
    uint32_t    dhcp_hi;
} wg_leases_t;

/* Diff-event hook. Fired once per (mac,ip) that appeared or disappeared
 * in dnsmasq.leases since the previous leases_reload(). `name` may be
 * "" if dnsmasq didn't record one. `reason` is non-NULL only for
 * removes (e.g. "expired" or "replaced"). */
typedef void (*wg_lease_change_cb_t)(void *arg,
                                     bool added,
                                     const uint8_t mac[6],
                                     uint32_t ip,
                                     const char *name,
                                     const char *reason);

void leases_init(wg_leases_t *t);
void leases_free(wg_leases_t *t);

/* Hook the lease table up to the persistent seen-db. The pointer is
 * borrowed (not owned). NULL is allowed and disables seen tracking. */
void leases_set_seen_db(wg_leases_t *t, wg_seen_db_t *db);

/* Register a change callback. Fires from inside leases_reload() after
 * the table has been rebuilt, so handlers see the new state. */
void leases_set_change_cb(wg_leases_t *t,
                          wg_lease_change_cb_t cb, void *arg);

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

/* Canonicalise a host key for use in pin/etc. tables: an IP literal is
 * normalised via ip_parse + ip_format; a known lease name is looked up
 * to itself; anything else is passed through. Caller-owned buffer. */
void leases_canon_key(const wg_leases_t *t, const char *key,
                      char *out, size_t cap);

/* Resolve a host key to its host-order IPv4. Accepts IP literals and
 * lease names. Returns true on success. */
bool leases_resolve_ip(const wg_leases_t *t, const char *key, uint32_t *out);

#endif
