#ifndef WGATECTL_CONFIG_H
#define WGATECTL_CONFIG_H

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    /* LAN capture */
    char     iface[32];         /* eth1 */
    char     network_cidr[32];  /* 10.6.6.0/24 */
    uint32_t net_addr;          /* host-order */
    uint32_t net_mask;
    int      host_octet_lo;     /* inclusive, default 64 */
    int      host_octet_hi;     /* exclusive, default 240 */

    /* External state files */
    char     dnsmasq_conf   [256];  /* /etc/dnsmasq.conf */
    char     dnsmasq_leases [256];  /* /var/lib/misc/dnsmasq.leases */
    char     blocks_json    [256];  /* /var/lib/wgatectl/blocks.json */

    /* Output */
    char     jsonl_dir      [256];  /* /var/log/wgatectl */
    int      jsonl_retain_days;     /* default 14 */

    /* IPC socket */
    char     sock_path      [128];  /* /run/wgatectl.sock */
    char     sock_group     [32];   /* wgate */

    /* Paths to external tools */
    char     iptables_bin   [96];   /* /sbin/iptables */
    char     ipset_bin      [96];   /* /sbin/ipset */

    int      flush_seconds;         /* default 60 */
} wg_cfg_t;

/* Populate cfg with compile-time defaults, overlay /etc/wgatectl.conf (if
 * present), then overlay env vars. Returns 0 on success, -1 if the CIDR or
 * similar required fields cannot be parsed. */
int cfg_load(wg_cfg_t *cfg, const char *conf_path_or_null);

#endif
