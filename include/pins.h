#ifndef WGATECTL_PINS_H
#define WGATECTL_PINS_H

#include "json.h"
#include "leases.h"
#include "schedule.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Per-host fixed-mode pin: regardless of the global schedule, an admin
 * may pin a host to {closed | filtered | open} for a time window. Pins
 * always have a strict expiry; there is no permanent pin (operators
 * wanting permanent access for a host should put it in WG_STATIC_CIDR).
 *
 * Realised at the kernel level via three ipsets — wgate_pin_open,
 * wgate_pin_closed, wgate_pin_filt — populated by pins_dump_to_ipsets.
 * iptables rules consult those ipsets ahead of the global-mode rules so
 * pins win over the global mode (see iptables.c). */

typedef struct wg_pins wg_pins_t;

wg_pins_t *pins_new(const char *pins_path, const char *ipset_bin);
void       pins_free(wg_pins_t *p);

int        pins_load(wg_pins_t *p);
int        pins_save(wg_pins_t *p);

/* Set or update a pin. `key` is canonicalised via leases (IP literal,
 * lease name, or pass-through). `until_wall` MUST be > now (caller
 * pre-validates). Returns 1 on add/update, 0 on no-op/error. */
int        pins_set(wg_pins_t *p, const wg_leases_t *leases,
                    const char *key, sch_mode_t mode,
                    int64_t until_wall, const char *reason);

/* Remove a pin by key. Returns 1 if removed, 0 otherwise. */
int        pins_remove(wg_pins_t *p, const wg_leases_t *leases,
                       const char *key);

/* Find the active pin for a host-order IP at now_wall. Sets *out_pinned
 * to true and returns the pinned mode if present; otherwise sets
 * *out_pinned to false and returns SCH_MODE_OPEN (caller should consult
 * the global mode). */
sch_mode_t pins_for_ip(const wg_pins_t *p, const wg_leases_t *leases,
                       uint32_t ip, int64_t now_wall, bool *out_pinned);

/* Prune expired pins; persist if anything changed. Cheap. */
void       pins_tick(wg_pins_t *p, int64_t now_wall);

/* Flush + repopulate the wgate_pin_* ipsets to reflect current pins.
 * Called from reconcile_apply_now and once per minute tick. */
void       pins_dump_to_ipsets(const wg_pins_t *p,
                               const wg_leases_t *leases,
                               int64_t now_wall);

/* For HTTP `GET /hosts` (per-lease pin emit) and `GET /status`. */
size_t     pins_count(const wg_pins_t *p, int64_t now_wall);
void       pins_dump_json(const wg_pins_t *p, int64_t now_wall, json_out_t *j);

/* For `handle_hosts`: walk all active pins. */
typedef struct {
    const char *key;
    sch_mode_t  mode;
    int64_t     until;
    const char *reason;
} wg_pin_view_t;
size_t     pins_active(const wg_pins_t *p, int64_t now_wall,
                       wg_pin_view_t *out, size_t cap);

#endif
