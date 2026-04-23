#ifndef WGATECTL_METRICS_H
#define WGATECTL_METRICS_H

#include "blocks.h"
#include "jsonl.h"
#include "leases.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct wg_metrics wg_metrics_t;

wg_metrics_t *metrics_new(void);
void          metrics_free(wg_metrics_t *m);

/* Called by the sniffer on every TCP packet that involves a LAN client.
 * `domain` is either a DNS-derived name or NULL (in which case the raw
 * server IP dotted-quad is bucketed). `wire_len` is the full L2+ packet
 * length. */
void metrics_observe_flow(wg_metrics_t *m,
                          uint32_t client_ip,
                          uint32_t server_ip,
                          const char *domain,
                          uint32_t wire_len);

/* Reserved hook (currently a no-op): the sniffer may call it on every
 * DNS query from a LAN client. Kept for symmetry and future use. */
void metrics_observe_dns_query(wg_metrics_t *m, uint32_t client_ip,
                               const char *qname);

/* Flush the per-minute traffic aggregator and a system-metrics event to
 * the JSONL writer. Clears the aggregator. */
void metrics_flush(wg_metrics_t *m,
                   jsonl_t *jl,
                   const wg_leases_t *leases,
                   const wg_blocks_t *blocks,
                   int64_t ts_secs);

/* Emit a control event (e.g. from an /hosts/{k}/allow API call). */
void metrics_emit_control(jsonl_t *jl, int64_t ts_secs,
                          const char *name, const char *ip_str,
                          const char *action, const char *reason);

#endif
