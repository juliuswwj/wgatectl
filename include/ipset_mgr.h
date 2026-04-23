#ifndef WGATECTL_IPSET_MGR_H
#define WGATECTL_IPSET_MGR_H

#include <stdbool.h>
#include <stdint.h>

typedef struct ipset_mgr ipset_mgr_t;

/* Create & flush the "wgate_allow" ipset. Returns NULL on failure. */
ipset_mgr_t *ipset_mgr_new(const char *ipset_bin);

/* Add a host-order IPv4 address to the ipset. Deduped by an in-memory LRU
 * so repeated DNS answers don't fork a subprocess each time. */
int ipset_mgr_add(ipset_mgr_t *m, uint32_t ip);

/* Returns true iff the QNAME (case-insensitive) matches a captive-check
 * FQDN (exact or suffix match, where the pattern starts after a dot). */
bool ipset_mgr_is_whitelist_fqdn(const char *qname);

/* Return the static list of whitelist FQDNs (NULL-terminated). */
const char *const *ipset_mgr_whitelist_fqdns(void);

void ipset_mgr_free(ipset_mgr_t *m);

#endif
