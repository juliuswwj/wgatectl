#ifndef WGATECTL_FILTERD_H
#define WGATECTL_FILTERD_H

#include "json.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Domain-driven IP filter: a list of domain suffixes (filterd.json) and a
 * passive-DNS-driven kernel ipset (`wgate_filterd`). The sniffer calls
 * filterd_observe_ip when a DNS A response's QNAME matches a configured
 * suffix; observed IPs queue in memory and are batched into the kernel
 * ipset once per minute by filterd_flush. ipset entries use a 600 s
 * timeout so a domain that hasn't resolved in 10 minutes ages out. */

typedef struct wg_filterd wg_filterd_t;

/* `filterd_path` is /opt/wgatectl/filterd.json (the domain table).
 * `ipset_bin` is the absolute path to the `ipset` binary; when present,
 * filterd_flush uses it to populate `wgate_filterd`. `legacy_path`, if
 * non-NULL, is read once on first load when `filterd_path` does not yet
 * exist — used for one-shot migration of /opt/wgatectl/supervised.json. */
wg_filterd_t *filterd_new(const char *filterd_path, const char *ipset_bin,
                          const char *legacy_path);
void          filterd_free(wg_filterd_t *f);

int           filterd_load(wg_filterd_t *f);
int           filterd_save(wg_filterd_t *f);

/* Case-insensitive label-boundary suffix match against the configured
 * targets. "example.com" matches "example.com" and "x.example.com",
 * NOT "abcexample.com". */
bool          filterd_domain_matches(const wg_filterd_t *f, const char *domain);

/* Sniffer hot path: observed an A-record IP for a matched QNAME. Cheap;
 * just enqueues. Safe to call many times per second. */
void          filterd_observe_ip(wg_filterd_t *f, uint32_t ip);

/* Drain the pending queue into the kernel `wgate_filterd` ipset. Each
 * entry is added with `timeout 600 -exist`, which refreshes existing
 * members in place. Call once per minute. */
void          filterd_flush(wg_filterd_t *f, int64_t now_wall);

/* Target list CRUD. Domain strings are stored lower-cased. Returns 1 on
 * change, 0 on no-op. */
int           filterd_add_target   (wg_filterd_t *f, const char *domain);
int           filterd_remove_target(wg_filterd_t *f, const char *domain);

/* Dump for HTTP `GET /filtered`. */
void          filterd_dump_json(const wg_filterd_t *f, json_out_t *j);

#endif
