#ifndef WGATECTL_SCHEDULE_H
#define WGATECTL_SCHEDULE_H

#include "config.h"
#include "json.h"
#include "jsonl.h"
#include "leases.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Three dhcp-range modes. Ordered lowest-to-most-permissive so it's easy to
 * reason about in logs; the numeric values are not otherwise significant. */
typedef enum {
    SCH_MODE_CLOSED   = 0,
    SCH_MODE_FILTERED = 1,
    SCH_MODE_OPEN     = 2
} sch_mode_t;

const char *sch_mode_name(sch_mode_t m);
bool        sch_mode_parse(const char *s, sch_mode_t *out);

typedef struct wg_schedule wg_schedule_t;

wg_schedule_t *schedule_new(const char *schedule_path);
void           schedule_free(wg_schedule_t *s);

int  schedule_load(wg_schedule_t *s);
int  schedule_save(wg_schedule_t *s);

/* Returns the effective mode right now and, optionally, the wall-clock
 * epoch of the next scheduled edge (base transition, override start, or
 * override expiry) strictly after `now_wall`. When there is no such edge
 * within a week the sentinel 0 is written. */
sch_mode_t schedule_effective_mode(const wg_schedule_t *s, int64_t now_wall,
                                   int64_t *next_transition_out);

/* Prune expired overrides; mark dirty; persist if anything changed. */
void schedule_tick(wg_schedule_t *s, int64_t now_wall);

/* One-shot overrides. id_out is filled with a short unique id ("ov_...")
 * on success; cap must be >= 24. Returns 0 on success, -1 on error. */
int  schedule_override_add(wg_schedule_t *s, int64_t at, sch_mode_t mode,
                           int64_t expires_at, const char *reason,
                           char *id_out, size_t cap);
int  schedule_override_remove(wg_schedule_t *s, const char *id);

/* Dump the current state for GET /schedule. */
void schedule_dump_json(const wg_schedule_t *s, int64_t now_wall,
                        json_out_t *j);

#endif
