#ifndef WGATECTL_SNIFFER_H
#define WGATECTL_SNIFFER_H

#include "filterd.h"
#include "ipset_mgr.h"
#include "metrics.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct wg_sniffer wg_sniffer_t;

typedef struct {
    const char    *iface;
    uint32_t       net_addr;       /* host-order */
    uint32_t       net_mask;
    ipset_mgr_t   *ipset;
    wg_metrics_t  *metrics;
    wg_filterd_t  *filterd;
} wg_sniffer_cfg_t;

wg_sniffer_t *sniffer_open(const wg_sniffer_cfg_t *cfg);
int           sniffer_fd  (const wg_sniffer_t *s);
int           sniffer_poll(wg_sniffer_t *s);   /* pcap_dispatch */
void          sniffer_close(wg_sniffer_t *s);

#endif
