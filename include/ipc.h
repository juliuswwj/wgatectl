#ifndef WGATECTL_IPC_H
#define WGATECTL_IPC_H

#include "blocks.h"
#include "config.h"
#include "iptables.h"
#include "jsonl.h"
#include "leases.h"

#include <stdbool.h>
#include <stdint.h>

/* Forward declarations: ipc.h should not pull in schedule/supervisor. */
typedef struct wg_schedule   wg_schedule_t;
typedef struct wg_supervisor wg_supervisor_t;
struct wg_arp_bind;
typedef struct wg_arp_bind wg_arp_bind_t;

/* Application hooks the HTTP handlers call into. */
typedef struct {
    wg_cfg_t        *cfg;
    wg_leases_t     *leases;
    wg_blocks_t     *blocks;
    wg_iptables_t   *ipt;
    wg_arp_bind_t   *ab;
    jsonl_t         *jl;
    wg_schedule_t   *sched;
    wg_supervisor_t *sup;
    uint64_t         started_mono_ns;

    /* Called by IPC handlers after mutating state. The callback MUST NOT
     * run iptables synchronously — it is expected to coalesce requests
     * through a debouncer. Cleared by default (pointer-NULL = no-op). */
    void           (*reconcile_request_cb)(void *arg);
    void            *reconcile_cb_arg;
} wg_ipc_app_t;

typedef struct wg_ipc wg_ipc_t;

wg_ipc_t *ipc_open(const wg_cfg_t *cfg, wg_ipc_app_t *app);
int       ipc_fd  (const wg_ipc_t *ipc);

int       ipc_accept(wg_ipc_t *ipc);

/* Run one pass of the client state machine for fd. Returns the set of
 * epoll event flags the client currently wants (EPOLLIN while reading,
 * EPOLLOUT while sending the response). Returns 0 if the client was
 * reset and fd was closed. */
unsigned int ipc_on_client_event(wg_ipc_t *ipc, int fd);

int       ipc_owns_fd(const wg_ipc_t *ipc, int fd);
int       ipc_next_new_client(wg_ipc_t *ipc);

/* Forcibly reap clients whose deadline has passed; returns the count
 * of clients closed. Caller passes a CLOCK_MONOTONIC nanosecond stamp. */
int       ipc_sweep_timeouts(wg_ipc_t *ipc, uint64_t now_ns);

void      ipc_close(wg_ipc_t *ipc);

#endif
