#ifndef WGATECTL_SCHEDULE_H
#define WGATECTL_SCHEDULE_H

#include "blocks.h"
#include "config.h"
#include "iptables.h"
#include "json.h"
#include "jsonl.h"
#include "leases.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Three dhcp-range modes. Ordered lowest-to-most-permissive so it's easy to
 * reason about in logs; the numeric values are not otherwise significant. */
typedef enum {
    SCH_MODE_CLOSED     = 0,
    SCH_MODE_SUPERVISED = 1,
    SCH_MODE_OPEN       = 2
} sch_mode_t;

const char *sch_mode_name(sch_mode_t m);
bool        sch_mode_parse(const char *s, sch_mode_t *out);

typedef struct wg_schedule   wg_schedule_t;
typedef struct wg_supervisor wg_supervisor_t;   /* forward — see supervisor.h */

wg_schedule_t *schedule_new(const char *schedule_path, const char *grants_path);
void           schedule_free(wg_schedule_t *s);

int  schedule_load(wg_schedule_t *s);
int  schedule_save(wg_schedule_t *s);

/* Returns the effective mode right now and, optionally, the wall-clock
 * epoch of the next scheduled edge (base transition, override start, or
 * override expiry) strictly after `now_wall`. When there is no such edge
 * within a week the sentinel 0 is written. */
sch_mode_t schedule_effective_mode(const wg_schedule_t *s, int64_t now_wall,
                                   int64_t *next_transition_out);

/* Prune expired overrides/grants; mark dirty; persist if anything changed. */
void schedule_tick(wg_schedule_t *s, int64_t now_wall);

/* One-shot overrides. id_out is filled with a short unique id ("ov_...")
 * on success; cap must be >= 24. Returns 0 on success, -1 on error. */
int  schedule_override_add(wg_schedule_t *s, int64_t at, sch_mode_t mode,
                           int64_t expires_at, const char *reason,
                           char *id_out, size_t cap);
int  schedule_override_remove(wg_schedule_t *s, const char *id);

/* Per-device timed grants. `key` is canonicalised via leases. Returns 1
 * on add/update, 0 on no-op. */
int  schedule_grant_add(wg_schedule_t *s, const wg_leases_t *leases,
                        const char *key, int minutes, const char *reason);

/* Same as schedule_grant_add but takes the absolute wall-clock expiry
 * instead of a minutes duration. until_wall must be > now_wall; callers
 * pre-validate. */
int  schedule_grant_add_until(wg_schedule_t *s, const wg_leases_t *leases,
                              const char *key, int64_t until_wall,
                              const char *reason);

int  schedule_grant_remove(wg_schedule_t *s, const wg_leases_t *leases,
                           const char *key);
bool schedule_grant_active_ip(const wg_schedule_t *s,
                              const wg_leases_t *leases,
                              uint32_t ip, int64_t now_wall);

/* Enumerate host-order IPs with an active grant at now_wall into out.
 * Writes up to cap entries; returns the count actually written. */
size_t schedule_active_grant_ips(const wg_schedule_t *s,
                                 const wg_leases_t *leases,
                                 int64_t now_wall,
                                 uint32_t *out, size_t cap);

/* Dump the current state for GET /schedule. */
void schedule_dump_json(const wg_schedule_t *s, int64_t now_wall,
                        json_out_t *j);

/* Compute the effective LAN-IP block set given current schedule + supervisor
 * state + permanent blocks. Initialises *out and fills it. */
void schedule_compute_blockset(const wg_schedule_t *s,
                               const wg_supervisor_t *sup,
                               const wg_blocks_t *blocks,
                               const wg_leases_t *leases,
                               const wg_cfg_t *cfg,
                               int64_t now_wall,
                               wg_block_set_t *out);

#endif
