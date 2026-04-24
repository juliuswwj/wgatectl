#include "arp_bind.h"
#include "blocks.h"
#include "config.h"
#include "ipc.h"
#include "ipset_mgr.h"
#include "iptables.h"
#include "jsonl.h"
#include "leases.h"
#include "log.h"
#include "metrics.h"
#include "schedule.h"
#include "sniffer.h"
#include "supervisor.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

/* Minimum seconds between iptables_reconcile passes. Change events that
 * arrive inside the window are coalesced into a single reconcile fired
 * as soon as the window elapses. Keep small enough that UI "block X"
 * feels responsive but large enough that an API flood cannot burn the
 * netfilter fast path. */
#define RECONCILE_MIN_INTERVAL_S 5

typedef struct {
    wg_cfg_t         cfg;
    wg_leases_t      leases;
    wg_blocks_t      blocks;
    wg_iptables_t    ipt;
    wg_arp_bind_t    ab;
    ipset_mgr_t     *ipset;
    wg_metrics_t    *metrics;
    jsonl_t         *jl;
    wg_schedule_t   *sched;
    wg_supervisor_t *sup;
    wg_sniffer_t    *sniffer;
    wg_ipc_t        *ipc;
    wg_ipc_app_t     app;

    int              epfd;
    int              tfd;
    int              sfd;

    int              last_flush_minute;
    sch_mode_t       last_mode;
    bool             have_last_mode;
    int              stopping;

    /* Reconcile gate (see RECONCILE_MIN_INTERVAL_S above). */
    int64_t          reconcile_last_s;
    bool             reconcile_pending;
} wg_state_t;

enum { TAG_TIMER = 1, TAG_SIGNAL, TAG_PCAP, TAG_IPC_LISTEN, TAG_IPC_CLIENT };

typedef struct {
    int      tag;
    int      fd;
    uint32_t events;    /* currently registered epoll events (clients only) */
} ep_ref_t;

static ep_ref_t g_timer_ref, g_signal_ref, g_pcap_ref, g_ipc_listen_ref;
static ep_ref_t g_client_refs[32];

static ep_ref_t *alloc_client_ref(int fd) {
    for (size_t i = 0; i < sizeof(g_client_refs) / sizeof(*g_client_refs); i++) {
        if (g_client_refs[i].fd < 0) {
            g_client_refs[i].tag    = TAG_IPC_CLIENT;
            g_client_refs[i].fd     = fd;
            g_client_refs[i].events = 0;
            return &g_client_refs[i];
        }
    }
    return NULL;
}

static void release_client_ref(int fd) {
    for (size_t i = 0; i < sizeof(g_client_refs) / sizeof(*g_client_refs); i++) {
        if (g_client_refs[i].fd == fd) {
            g_client_refs[i].fd     = -1;
            g_client_refs[i].events = 0;
            return;
        }
    }
}

/* ------------------------- setup helpers ------------------------- */

static int ep_add(int epfd, int fd, uint32_t events, void *ptr) {
    struct epoll_event ev = { .events = events, .data = { .ptr = ptr } };
    return epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
}

static void sup_observe_cb(uint32_t client_ip, const char *domain,
                           uint64_t bytes, uint32_t pkts, void *arg) {
    (void)pkts;
    wg_state_t *st = arg;
    supervisor_observe(st->sup, client_ip, domain, bytes);
}

/* Actually run iptables reconcile. Called either directly from code paths
 * where immediate application is required (startup), or from the gate
 * below when the debounce window has elapsed. */
static void reconcile_apply_now(wg_state_t *st) {
    int64_t now = now_wall_s();
    sch_mode_t mode = schedule_effective_mode(st->sched, now, NULL);

    wg_block_set_t desired;
    schedule_compute_blockset(st->sched, st->sup, &st->blocks, &st->leases,
                              &st->cfg, now, &desired);

    /* Active grants — used in closed mode to punch through the bulk
     * -i lan DROP. GRANTS_MAX is 512; cap the snapshot accordingly. */
    wg_block_set_t grants;
    wg_block_set_init(&grants);
    {
        uint32_t gips[512];
        size_t n = schedule_active_grant_ips(st->sched, &st->leases, now,
                                             gips, sizeof(gips)/sizeof(*gips));
        for (size_t i = 0; i < n; i++) wg_block_set_add(&grants, gips[i]);
    }

    iptables_reconcile(&st->ipt,
                       st->cfg.iface, st->cfg.static_cidr,
                       st->cfg.net_addr, st->cfg.net_mask,
                       &desired, &grants, mode == SCH_MODE_CLOSED,
                       NULL, NULL);
    wg_block_set_free(&grants);
    wg_block_set_free(&desired);
    st->reconcile_last_s  = now;
    st->reconcile_pending = false;
}

/* Rate-limited reconcile entry point. At most one iptables pass every
 * RECONCILE_MIN_INTERVAL_S seconds; if called more often, later requests
 * are coalesced and flushed when the window elapses (see on_timer). */
static void reconcile_request(wg_state_t *st) {
    int64_t now = now_wall_s();
    if (now - st->reconcile_last_s >= RECONCILE_MIN_INTERVAL_S) {
        reconcile_apply_now(st);
    } else {
        st->reconcile_pending = true;
    }
}

static void reconcile_request_cb(void *arg) { reconcile_request(arg); }

static void do_minute_flush(wg_state_t *st) {
    int64_t now = now_wall_s();

    /* drop expired overrides/grants before evaluation */
    schedule_tick(st->sched, now);

    /* evaluate the mode we're in for this minute */
    sch_mode_t mode = schedule_effective_mode(st->sched, now, NULL);

    /* supervisor: observe per-bucket traffic (only in supervised mode),
     * then commit the minute; outside supervised mode, drop any stale
     * matched state so the counter doesn't linger across mode swaps. */
    if (mode == SCH_MODE_SUPERVISED) {
        metrics_foreach_bucket(st->metrics, sup_observe_cb, st);
        supervisor_commit_minute(st->sup, &st->leases, st->jl, now);
    } else {
        supervisor_drop_minute(st->sup);
    }

    /* expire any supervised-mode 1-hour blocks whose clock ran out */
    supervisor_tick(st->sup, &st->leases, now);

    /* Go through the gate so that a minute tick that coincides with an
     * API burst still only produces one iptables pass. */
    reconcile_request(st);

    /* flush the per-minute traffic aggregator */
    metrics_flush(st->metrics, st->jl, &st->leases, &st->blocks, now);

    jsonl_sync(st->jl);

    /* emit a control event when the mode transitions, and on entering
     * a permissive mode (supervised / open) auto-clear the block list
     * so the user doesn't have to hand-allow each device every morning. */
    if (!st->have_last_mode || mode != st->last_mode) {
        if (st->have_last_mode) {
            metrics_emit_control(st->jl, now, "dhcp-range", NULL,
                                 sch_mode_name(mode), "schedule");
        }

        bool entering_permissive =
            st->have_last_mode &&
            (mode == SCH_MODE_SUPERVISED || mode == SCH_MODE_OPEN);
        if (entering_permissive && st->blocks.n > 0) {
            for (size_t i = 0; i < st->blocks.n; i++) {
                const wg_block_item_t *it = &st->blocks.items[i];
                uint32_t ip;
                char ipbuf[16] = "";
                if (blocks_resolve_ip(&st->leases, it->key, &ip))
                    ip_format(ip, ipbuf);
                metrics_emit_control(st->jl, now, it->key,
                                     ipbuf[0] ? ipbuf : NULL,
                                     "allow", "auto-open");
            }
            blocks_clear(&st->blocks);
            blocks_save(&st->blocks);
            reconcile_request(st);
        }

        st->last_mode      = mode;
        st->have_last_mode = true;
    }
}

static int setup_timer(wg_state_t *st) {
    st->tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (st->tfd < 0) { LOG_E("timerfd: %s", strerror(errno)); return -1; }
    struct itimerspec it = {
        .it_interval = { .tv_sec = 1, .tv_nsec = 0 },
        .it_value    = { .tv_sec = 1, .tv_nsec = 0 }
    };
    if (timerfd_settime(st->tfd, 0, &it, NULL) < 0) {
        LOG_E("timerfd_settime: %s", strerror(errno));
        return -1;
    }
    return 0;
}

static int setup_signalfd(wg_state_t *st) {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGHUP);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) return -1;
    st->sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (st->sfd < 0) { LOG_E("signalfd: %s", strerror(errno)); return -1; }
    return 0;
}

static int init_all(wg_state_t *st, const char *conf_override) {
    memset(st, 0, sizeof(*st));
    for (size_t i = 0; i < sizeof(g_client_refs) / sizeof(*g_client_refs); i++)
        g_client_refs[i].fd = -1;
    st->last_flush_minute = -1;

    if (cfg_load(&st->cfg, conf_override) < 0) return -1;
    logger_init(0);

    leases_init(&st->leases);
    leases_reload(&st->leases, st->cfg.dnsmasq_conf, st->cfg.dnsmasq_leases);

    arp_bind_init(&st->ab, st->cfg.ip_bin, st->cfg.iface, st->cfg.static_cidr);
    arp_bind_apply(&st->ab, &st->leases);

    blocks_init(&st->blocks, st->cfg.blocks_json);
    blocks_load(&st->blocks);

    st->sched = schedule_new(st->cfg.schedule_json, st->cfg.grants_json);
    if (!st->sched) return -1;
    schedule_load(st->sched);

    st->sup = supervisor_new(st->cfg.supervised_json, st->cfg.triggers_json);
    if (!st->sup) return -1;
    supervisor_configure(st->sup,
                         st->cfg.supervised_threshold_min,
                         st->cfg.supervised_cooldown_min,
                         st->cfg.supervised_min_bytes_per_min);
    supervisor_load(st->sup);

    strncpy(st->ipt.iptables_bin, st->cfg.iptables_bin,
            sizeof(st->ipt.iptables_bin) - 1);

    st->ipset = ipset_mgr_new(st->cfg.ipset_bin);
    if (!st->ipset) return -1;
    /* iptables FORWARD reconcile below installs the wgate_allow ACCEPT
     * rules (and the rest of the wgatectl block) — no separate bootstrap. */

    st->jl = jsonl_open(st->cfg.jsonl_dir, st->cfg.jsonl_retain_days);
    if (!st->jl) return -1;

    st->metrics = metrics_new();
    if (!st->metrics) return -1;

    wg_sniffer_cfg_t scfg = {
        .iface    = st->cfg.iface,
        .net_addr = st->cfg.net_addr,
        .net_mask = st->cfg.net_mask,
        .ipset    = st->ipset,
        .metrics  = st->metrics
    };
    st->sniffer = sniffer_open(&scfg);
    if (!st->sniffer) return -1;

    st->app.cfg    = &st->cfg;
    st->app.leases = &st->leases;
    st->app.blocks = &st->blocks;
    st->app.ipt    = &st->ipt;
    st->app.jl     = st->jl;
    st->app.sched  = st->sched;
    st->app.sup    = st->sup;
    st->app.ab     = &st->ab;
    st->app.reconcile_request_cb = reconcile_request_cb;
    st->app.reconcile_cb_arg     = st;

    st->ipc = ipc_open(&st->cfg, &st->app);
    if (!st->ipc) return -1;

    st->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (st->epfd < 0) { LOG_E("epoll_create1: %s", strerror(errno)); return -1; }

    if (setup_timer(st)    < 0) return -1;
    if (setup_signalfd(st) < 0) return -1;

    g_timer_ref      = (ep_ref_t){ TAG_TIMER,      st->tfd,                 0 };
    g_signal_ref     = (ep_ref_t){ TAG_SIGNAL,     st->sfd,                 0 };
    g_pcap_ref       = (ep_ref_t){ TAG_PCAP,       sniffer_fd(st->sniffer), 0 };
    g_ipc_listen_ref = (ep_ref_t){ TAG_IPC_LISTEN, ipc_fd(st->ipc),         0 };

    if (ep_add(st->epfd, st->tfd,                 EPOLLIN, &g_timer_ref)    < 0) return -1;
    if (ep_add(st->epfd, st->sfd,                 EPOLLIN, &g_signal_ref)   < 0) return -1;
    if (ep_add(st->epfd, sniffer_fd(st->sniffer), EPOLLIN, &g_pcap_ref)     < 0) return -1;
    if (ep_add(st->epfd, ipc_fd(st->ipc),         EPOLLIN, &g_ipc_listen_ref) < 0) return -1;

    /* initial reconcile from persisted blocks + current schedule state */
    int64_t init_now = now_wall_s();
    schedule_tick(st->sched, init_now);
    supervisor_tick(st->sup, &st->leases, init_now);
    st->last_mode      = schedule_effective_mode(st->sched, init_now, NULL);
    st->have_last_mode = true;
    /* Prime the gate so startup applies immediately regardless of prior
     * daemon runs, then arm it for RECONCILE_MIN_INTERVAL_S onward. */
    st->reconcile_last_s  = 0;
    st->reconcile_pending = false;
    reconcile_apply_now(st);

    LOG_I("wgatectl: up (iface=%s network=%s blocks=%zu mode=%s)",
          st->cfg.iface, st->cfg.network_cidr, st->blocks.n,
          sch_mode_name(st->last_mode));
    return 0;
}

/* ------------------------- loop ------------------------- */

/* Drop any ep_ref_t slots whose client fd was reaped (by a timeout sweep
 * or by ipc_on_client_event returning 0). Safe to call every tick. */
static void prune_client_refs(wg_state_t *st) {
    for (size_t i = 0; i < sizeof(g_client_refs) / sizeof(*g_client_refs); i++) {
        if (g_client_refs[i].fd < 0) continue;
        if (!ipc_owns_fd(st->ipc, g_client_refs[i].fd)) {
            g_client_refs[i].fd     = -1;
            g_client_refs[i].events = 0;
        }
    }
}

static void on_timer(wg_state_t *st) {
    uint64_t exp;
    (void)read(st->tfd, &exp, sizeof(exp));

    /* reap idle/slow IPC clients first so they don't hold epoll slots */
    if (ipc_sweep_timeouts(st->ipc, now_mono_ns()) > 0) {
        prune_client_refs(st);
    }

    /* flush any coalesced reconcile whose window has now elapsed */
    if (st->reconcile_pending &&
        (now_wall_s() - st->reconcile_last_s) >= RECONCILE_MIN_INTERVAL_S) {
        reconcile_apply_now(st);
    }

    int hm;
    now_hm_wday(&hm, NULL);
    if (hm != st->last_flush_minute) {
        st->last_flush_minute = hm;
        do_minute_flush(st);
    }
}

static void on_signal(wg_state_t *st) {
    struct signalfd_siginfo si;
    while (read(st->sfd, &si, sizeof(si)) == sizeof(si)) {
        if (si.ssi_signo == SIGHUP) {
            LOG_I("SIGHUP: reloading dnsmasq.conf + schedule + supervised");
            leases_reload(&st->leases, st->cfg.dnsmasq_conf,
                          st->cfg.dnsmasq_leases);
            arp_bind_apply(&st->ab, &st->leases);
            schedule_load(st->sched);
            supervisor_load(st->sup);
            int64_t now = now_wall_s();
            schedule_tick(st->sched, now);
            supervisor_tick(st->sup, &st->leases, now);
            reconcile_request(st);
        } else {
            LOG_I("signal %u: shutting down", si.ssi_signo);
            st->stopping = 1;
        }
    }
}

#define CLIENT_EPOLL_COMMON (EPOLLHUP | EPOLLRDHUP | EPOLLERR)

static void on_ipc_listen(wg_state_t *st) {
    ipc_accept(st->ipc);
    int fd;
    while ((fd = ipc_next_new_client(st->ipc)) >= 0) {
        ep_ref_t *ref = alloc_client_ref(fd);
        if (!ref) { LOG_W("too many epoll client refs"); continue; }
        uint32_t ev = EPOLLIN | CLIENT_EPOLL_COMMON;
        if (ep_add(st->epfd, fd, ev, ref) < 0) {
            LOG_W("ep_add client: %s", strerror(errno));
            release_client_ref(fd);
            continue;
        }
        ref->events = ev;
    }
}

/* After ipc_on_client_event, update the client's epoll mask to match
 * the state machine's need (reading → EPOLLIN, writing → EPOLLOUT).
 * Called only when the fd is still owned by ipc. */
static void update_client_epoll(wg_state_t *st, ep_ref_t *ref,
                                uint32_t wants) {
    uint32_t want = (wants & (EPOLLIN | EPOLLOUT)) | CLIENT_EPOLL_COMMON;
    if (want == ref->events) return;
    struct epoll_event ev = { .events = want, .data = { .ptr = ref } };
    if (epoll_ctl(st->epfd, EPOLL_CTL_MOD, ref->fd, &ev) < 0) {
        LOG_W("epoll_ctl MOD fd=%d: %s", ref->fd, strerror(errno));
        return;
    }
    ref->events = want;
}

static int loop(wg_state_t *st) {
    struct epoll_event events[32];
    while (!st->stopping) {
        int n = epoll_wait(st->epfd, events,
                           sizeof(events) / sizeof(*events), -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            LOG_E("epoll_wait: %s", strerror(errno));
            return -1;
        }
        for (int i = 0; i < n; i++) {
            ep_ref_t *ref = events[i].data.ptr;
            switch (ref->tag) {
                case TAG_TIMER:       on_timer (st); break;
                case TAG_SIGNAL:      on_signal(st); break;
                case TAG_PCAP:        sniffer_poll(st->sniffer); break;
                case TAG_IPC_LISTEN:  on_ipc_listen(st); break;
                case TAG_IPC_CLIENT: {
                    unsigned int wants = ipc_on_client_event(st->ipc, ref->fd);
                    if (wants == 0 || !ipc_owns_fd(st->ipc, ref->fd)) {
                        /* fd was closed by ipc (reset/timeout/done) */
                        release_client_ref(ref->fd);
                    } else {
                        update_client_epoll(st, ref, wants);
                    }
                    break;
                }
            }
        }
    }
    return 0;
}

static void shutdown_all(wg_state_t *st) {
    if (st->metrics && st->jl)
        metrics_flush(st->metrics, st->jl, &st->leases, &st->blocks,
                      now_wall_s());

    blocks_save(&st->blocks);
    if (st->sched) schedule_save(st->sched);
    if (st->sup)   supervisor_save(st->sup);

    if (st->ipc)     ipc_close(st->ipc);
    if (st->sniffer) sniffer_close(st->sniffer);
    if (st->metrics) metrics_free(st->metrics);
    if (st->jl)      jsonl_close(st->jl);
    if (st->ipset)   ipset_mgr_free(st->ipset);

    if (st->sched) schedule_free(st->sched);
    if (st->sup)   supervisor_free(st->sup);

    arp_bind_shutdown(&st->ab);
    arp_bind_free(&st->ab);

    blocks_free(&st->blocks);
    leases_free(&st->leases);

    if (st->tfd  >= 0) close(st->tfd);
    if (st->sfd  >= 0) close(st->sfd);
    if (st->epfd >= 0) close(st->epfd);
}

int main(int argc, char **argv) {
    const char *conf = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) conf = argv[++i];
        else if (strcmp(argv[i], "-v") == 0) logger_init(1);
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("usage: %s [-c /etc/wgatectl.conf] [-v]\n", argv[0]);
            return 0;
        }
    }

    /* A wgate-group client disconnecting mid-response would otherwise
     * kill the daemon via the default SIGPIPE action; ignore it and let
     * the bare write() return EPIPE which ipc.c already handles. */
    signal(SIGPIPE, SIG_IGN);

    wg_state_t st;
    if (init_all(&st, conf) < 0) {
        shutdown_all(&st);
        return 1;
    }
    int rc = loop(&st);
    shutdown_all(&st);
    return rc == 0 ? 0 : 1;
}
