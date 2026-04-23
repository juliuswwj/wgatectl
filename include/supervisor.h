#ifndef WGATECTL_SUPERVISOR_H
#define WGATECTL_SUPERVISOR_H

#include "blocks.h"
#include "json.h"
#include "jsonl.h"
#include "leases.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The supervisor watches per-client per-minute traffic: if a device's
 * traffic includes any domain listed in supervised.json for 5 consecutive
 * minutes, the device is fully blocked for 1 hour. After the cool-down the
 * counter is reset. Detection only runs while the dhcp-range mode is
 * `supervised`; the caller controls that. */

typedef struct wg_supervisor wg_supervisor_t;

wg_supervisor_t *supervisor_new(const char *supervised_path,
                                const char *triggers_path);
void             supervisor_free(wg_supervisor_t *s);

int  supervisor_load(wg_supervisor_t *s);
int  supervisor_save(wg_supervisor_t *s);

/* Does the given domain match any supervised target (case-insensitive
 * suffix match, boundary-aligned)?  Patterns like `example.com` match
 * `example.com` and `*.example.com` exactly; `a.bexample.com` does NOT
 * match `example.com`. */
bool supervisor_domain_matches(const wg_supervisor_t *s, const char *domain);

/* Per-minute observation. Called once per (client_ip, domain) bucket from
 * the minute flush, BEFORE the metrics aggregator is reset. */
void supervisor_observe(wg_supervisor_t *s, uint32_t client_ip,
                        const char *domain);

/* Close out the minute: increment counters for clients that matched at
 * least once, reset counters for tracked clients that didn't match, and
 * fire triggers (1-hour blocks) when counters reach the threshold.
 * Emits control events with reason="supervised". */
void supervisor_commit_minute(wg_supervisor_t *s,
                              const wg_leases_t *leases,
                              jsonl_t *jl, int64_t now_wall);

/* Reset (clear) the per-minute matched state without incrementing. Used
 * when the daemon is NOT in supervised mode so a leftover observation from
 * an earlier minute doesn't carry over. Cheap; safe to call every minute. */
void supervisor_drop_minute(wg_supervisor_t *s);

/* Prune expired triggers; on expiry the associated client's counter is
 * reset to 0 (per-user requirement: re-arm fresh after cool-down). */
void supervisor_tick(wg_supervisor_t *s,
                     const wg_leases_t *leases,
                     int64_t now_wall);

/* Returns true iff any trigger for ip is still active. */
bool supervisor_ip_triggered(const wg_supervisor_t *s,
                             const wg_leases_t *leases,
                             uint32_t ip, int64_t now_wall);

/* Fill out[] with the host-order IPs of currently triggered devices.
 * Returns the number actually written (<= cap). */
size_t supervisor_triggered_ips(const wg_supervisor_t *s,
                                const wg_leases_t *leases,
                                int64_t now_wall,
                                uint32_t *out, size_t cap);

/* Target list CRUD. Domain strings are stored lower-cased. Returns 1 on
 * change, 0 on no-op. */
int  supervisor_add_target   (wg_supervisor_t *s, const char *domain);
int  supervisor_remove_target(wg_supervisor_t *s, const char *domain);

/* Dumps for HTTP. */
void supervisor_dump_json    (const wg_supervisor_t *s, int64_t now_wall,
                              json_out_t *j);

#endif
