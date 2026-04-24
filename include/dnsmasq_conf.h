#ifndef WGATECTL_DNSMASQ_CONF_H
#define WGATECTL_DNSMASQ_CONF_H

#include <stdbool.h>
#include <stdint.h>

typedef enum {
    DNS_NAME_OK = 0,
    DNS_NAME_INVALID,        /* malformed new name */
    DNS_NAME_DUPLICATE,      /* another host already uses this name */
    DNS_NAME_NO_MAC,         /* caller passed an all-zero MAC */
    DNS_NAME_IO,             /* read/parse/write failure */
} dnsmasq_name_rc_t;

/* True iff `s` is an acceptable hostname: 1..63 chars, leading alnum,
 * rest of [A-Za-z0-9._-]. We intentionally stop short of full RFC-1035
 * — dnsmasq accepts what Linux accepts, and we just need to reject
 * commas / equals / whitespace that would corrupt the conf file. */
bool dnsmasq_name_is_valid(const char *s);

/* Update (or insert) a dhcp-host=MAC,IP,NAME line in `conf_path` so that
 * the host identified by `mac` is named `name`. If `ip != 0` it is
 * recorded/updated as the static-assignment IP.
 *
 * Uniqueness: if any other dhcp-host entry in the file already has
 * `name`, returns DNS_NAME_DUPLICATE without touching the file.
 *
 * On success, sets *changed_out = true when the file was actually
 * rewritten (false if the entry already matched). */
dnsmasq_name_rc_t dnsmasq_set_host_name(const char *conf_path,
                                        const uint8_t mac[6],
                                        uint32_t ip,
                                        const char *name,
                                        bool *changed_out);

#endif
