#include "blocks.h"
#include "config.h"
#include "ipc.h"
#include "ipset_mgr.h"
#include "iptables.h"
#include "jsonl.h"
#include "leases.h"
#include "log.h"
#include "metrics.h"
#include "sniffer.h"
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

typedef struct {
    wg_cfg_t       cfg;
    wg_leases_t    leases;
    wg_blocks_t    blocks;
    wg_iptables_t  ipt;
    ipset_mgr_t   *ipset;
    wg_metrics_t  *metrics;
    jsonl_t       *jl;
    wg_sniffer_t  *sniffer;
    wg_ipc_t      *ipc;
    wg_ipc_app_t   app;

    int            epfd;
    int            tfd;
    int            sfd;

    int            last_flush_minute;
    int            stopping;
} wg_state_t;

enum { TAG_TIMER = 1, TAG_SIGNAL, TAG_PCAP, TAG_IPC_LISTEN, TAG_IPC_CLIENT };

typedef struct {
    int tag;
    int fd;
} ep_ref_t;

static ep_ref_t g_timer_ref, g_signal_ref, g_pcap_ref, g_ipc_listen_ref;
static ep_ref_t g_client_refs[32];

static ep_ref_t *alloc_client_ref(int fd) {
    for (size_t i = 0; i < sizeof(g_client_refs) / sizeof(*g_client_refs); i++) {
        if (g_client_refs[i].fd < 0) {
            g_client_refs[i].tag = TAG_IPC_CLIENT;
            g_client_refs[i].fd  = fd;
            return &g_client_refs[i];
        }
    }
    return NULL;
}

static void release_client_ref(int fd) {
    for (size_t i = 0; i < sizeof(g_client_refs) / sizeof(*g_client_refs); i++) {
        if (g_client_refs[i].fd == fd) { g_client_refs[i].fd = -1; return; }
    }
}

/* ------------------------- setup helpers ------------------------- */

static int ep_add(int epfd, int fd, uint32_t events, void *ptr) {
    struct epoll_event ev = { .events = events, .data = { .ptr = ptr } };
    return epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
}

static void rebuild_blockset(const wg_state_t *st, wg_block_set_t *out) {
    wg_block_set_init(out);
    const wg_blocks_t *b = &st->blocks;
    for (size_t i = 0; i < b->n; i++) {
        uint32_t ip;
        if (!blocks_resolve_ip(&st->leases, b->keys[i], &ip)) continue;
        if (!ip_in_subnet(ip, st->cfg.net_addr, st->cfg.net_mask)) continue;
        wg_block_set_add(out, ip);
    }
}

static void do_minute_flush(wg_state_t *st) {
    /* reconcile iptables once per minute to self-heal any drift */
    wg_block_set_t desired;
    rebuild_blockset(st, &desired);
    iptables_reconcile(&st->ipt, st->cfg.net_addr, st->cfg.net_mask,
                       &desired, NULL, NULL);
    wg_block_set_free(&desired);

    /* flush the per-minute aggregator */
    metrics_flush(st->metrics, st->jl, &st->leases, &st->blocks, now_wall_s());

    jsonl_sync(st->jl);
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

    blocks_init(&st->blocks, st->cfg.blocks_json);
    blocks_load(&st->blocks);

    strncpy(st->ipt.iptables_bin, st->cfg.iptables_bin,
            sizeof(st->ipt.iptables_bin) - 1);

    st->ipset = ipset_mgr_new(st->cfg.ipset_bin);
    if (!st->ipset) return -1;
    iptables_bootstrap(&st->ipt, st->cfg.ipset_bin);

    st->jl = jsonl_open(st->cfg.jsonl_dir, st->cfg.jsonl_retain_days);
    if (!st->jl) return -1;

    st->metrics = metrics_new();
    if (!st->metrics) return -1;

    wg_sniffer_cfg_t scfg = {
        .iface         = st->cfg.iface,
        .net_addr      = st->cfg.net_addr,
        .net_mask      = st->cfg.net_mask,
        .host_octet_lo = st->cfg.host_octet_lo,
        .host_octet_hi = st->cfg.host_octet_hi,
        .ipset         = st->ipset,
        .metrics       = st->metrics
    };
    st->sniffer = sniffer_open(&scfg);
    if (!st->sniffer) return -1;

    st->app.cfg    = &st->cfg;
    st->app.leases = &st->leases;
    st->app.blocks = &st->blocks;
    st->app.ipt    = &st->ipt;
    st->app.jl     = st->jl;
    st->app.started_mono_ns = now_mono_ns();

    st->ipc = ipc_open(&st->cfg, &st->app);
    if (!st->ipc) return -1;

    st->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (st->epfd < 0) { LOG_E("epoll_create1: %s", strerror(errno)); return -1; }

    if (setup_timer(st)    < 0) return -1;
    if (setup_signalfd(st) < 0) return -1;

    g_timer_ref      = (ep_ref_t){ TAG_TIMER,      st->tfd };
    g_signal_ref     = (ep_ref_t){ TAG_SIGNAL,     st->sfd };
    g_pcap_ref       = (ep_ref_t){ TAG_PCAP,       sniffer_fd(st->sniffer) };
    g_ipc_listen_ref = (ep_ref_t){ TAG_IPC_LISTEN, ipc_fd(st->ipc) };

    if (ep_add(st->epfd, st->tfd,                 EPOLLIN, &g_timer_ref)    < 0) return -1;
    if (ep_add(st->epfd, st->sfd,                 EPOLLIN, &g_signal_ref)   < 0) return -1;
    if (ep_add(st->epfd, sniffer_fd(st->sniffer), EPOLLIN, &g_pcap_ref)     < 0) return -1;
    if (ep_add(st->epfd, ipc_fd(st->ipc),         EPOLLIN, &g_ipc_listen_ref) < 0) return -1;

    /* initial reconcile from persisted blocks */
    wg_block_set_t desired;
    rebuild_blockset(st, &desired);
    iptables_reconcile(&st->ipt, st->cfg.net_addr, st->cfg.net_mask,
                       &desired, NULL, NULL);
    wg_block_set_free(&desired);

    LOG_I("wgatectl: up (iface=%s network=%s blocks=%zu)",
          st->cfg.iface, st->cfg.network_cidr, st->blocks.n);
    return 0;
}

/* ------------------------- loop ------------------------- */

static void on_timer(wg_state_t *st) {
    uint64_t exp;
    (void)read(st->tfd, &exp, sizeof(exp));
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
            LOG_I("SIGHUP: reloading dnsmasq.conf");
            leases_reload(&st->leases, st->cfg.dnsmasq_conf,
                          st->cfg.dnsmasq_leases);
            wg_block_set_t desired;
            rebuild_blockset(st, &desired);
            iptables_reconcile(&st->ipt, st->cfg.net_addr, st->cfg.net_mask,
                               &desired, NULL, NULL);
            wg_block_set_free(&desired);
        } else {
            LOG_I("signal %u: shutting down", si.ssi_signo);
            st->stopping = 1;
        }
    }
}

static void on_ipc_listen(wg_state_t *st) {
    ipc_accept(st->ipc);
    int fd;
    while ((fd = ipc_next_new_client(st->ipc)) >= 0) {
        ep_ref_t *ref = alloc_client_ref(fd);
        if (!ref) { LOG_W("too many epoll client refs"); continue; }
        if (ep_add(st->epfd, fd, EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLERR, ref) < 0) {
            LOG_W("ep_add client: %s", strerror(errno));
            release_client_ref(fd);
        }
    }
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
                case TAG_IPC_CLIENT:
                    ipc_on_client_event(st->ipc, ref->fd);
                    if (!ipc_owns_fd(st->ipc, ref->fd)) {
                        epoll_ctl(st->epfd, EPOLL_CTL_DEL, ref->fd, NULL);
                        release_client_ref(ref->fd);
                    }
                    break;
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

    if (st->ipc)     ipc_close(st->ipc);
    if (st->sniffer) sniffer_close(st->sniffer);
    if (st->metrics) metrics_free(st->metrics);
    if (st->jl)      jsonl_close(st->jl);
    if (st->ipset)   ipset_mgr_free(st->ipset);

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

    wg_state_t st;
    if (init_all(&st, conf) < 0) {
        shutdown_all(&st);
        return 1;
    }
    int rc = loop(&st);
    shutdown_all(&st);
    return rc == 0 ? 0 : 1;
}
