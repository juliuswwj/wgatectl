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

    /* Static-assignment zone: CIDR (e.g. "10.6.6.0/27") that the gateway
     * exempts from all FORWARD filtering and proactively ARP-binds.  When
     * empty, there is no static exempt rule and no ARP binding. */
    char     static_cidr    [32];

    /* External state files */
    char     dnsmasq_conf   [256];  /* /etc/dnsmasq.conf */
    char     dnsmasq_leases [256];  /* /var/lib/misc/dnsmasq.leases */
    char     schedule_json  [256];  /* /opt/wgatectl/schedule.json */
    char     filterd_json   [256];  /* /opt/wgatectl/filterd.json */
    char     pins_json      [256];  /* /opt/wgatectl/pins.json */
    char     supervised_json[256];  /* /opt/wgatectl/supervised.json (legacy, one-shot import) */

    /* Output */
    char     jsonl_dir      [256];  /* /var/log/wgatectl */
    int      jsonl_retain_days;     /* default 14 */

    /* IPC socket */
    char     sock_path      [128];  /* /run/wgatectl.sock */
    char     sock_group     [32];   /* wgate */

    /* Paths to external tools */
    char     iptables_bin   [96];   /* /sbin/iptables */
    char     ipset_bin      [96];   /* /sbin/ipset */
    char     ip_bin         [96];   /* /sbin/ip  (iproute2) */

    /* Shell command that reloads dnsmasq after we rewrite
     * dnsmasq.conf (default: "systemctl restart dnsmasq"). Run via
     * /bin/sh -c, coalesced to one invocation per 5 s. */
    char     dnsmasq_reload_cmd[128];

    /* MAC address of the Proxmox host. POST /pve/wake sends a WoL magic
     * packet to the LAN broadcast (port 9) targeting this MAC. Empty
     * disables the endpoint. */
    char     pve_mac[18];

    int      flush_seconds;         /* default 60 */
} wg_cfg_t;

/* Populate cfg with compile-time defaults, overlay /etc/wgatectl.conf (if
 * present), then overlay env vars. Returns 0 on success, -1 if the CIDR or
 * similar required fields cannot be parsed. */
int cfg_load(wg_cfg_t *cfg, const char *conf_path_or_null);

#endif
