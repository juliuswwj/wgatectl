#ifndef WGATECTL_IPC_H
#define WGATECTL_IPC_H

#include "blocks.h"
#include "config.h"
#include "iptables.h"
#include "jsonl.h"
#include "leases.h"

#include <stdbool.h>
#include <stdint.h>

/* Application hooks the HTTP handlers call into. */
typedef struct {
    wg_cfg_t      *cfg;
    wg_leases_t   *leases;
    wg_blocks_t   *blocks;
    wg_iptables_t *ipt;
    jsonl_t       *jl;
    uint64_t       started_mono_ns;
} wg_ipc_app_t;

typedef struct wg_ipc wg_ipc_t;

wg_ipc_t *ipc_open(const wg_cfg_t *cfg, wg_ipc_app_t *app);
int       ipc_fd  (const wg_ipc_t *ipc);

int       ipc_accept(wg_ipc_t *ipc);
int       ipc_on_client_event(wg_ipc_t *ipc, int fd);
int       ipc_owns_fd(const wg_ipc_t *ipc, int fd);
int       ipc_next_new_client(wg_ipc_t *ipc);

void      ipc_close(wg_ipc_t *ipc);

#endif
