#include "arp_bind.h"
#include "log.h"
#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define WG_ARP_DUMMY_MAC "02:00:00:00:de:ad"

/* Upper bound on the number of ARP pins we'll install. Protects against a
 * user who puts a huge CIDR (/16 = 65k IPs) into WG_STATIC_CIDR. */
#define WG_ARP_MAX_PINS 1024

/* ----------------------------- exec helper ---------------------------- */

static int run_quiet(const char *bin, char *const argv[]) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, 1);
            dup2(devnull, 2);
            if (devnull > 2) close(devnull);
        }
        execv(bin, argv);
        _exit(127);
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) { /* EINTR retry */ }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
}

/* ----------------------------- MAC format ----------------------------- */

static void mac_buf(const uint8_t mac[6], char *out /* 18 */) {
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* ----------------------------- bound-set ------------------------------ */

static void bound_set_replace(wg_arp_bind_t *ab,
                              const uint32_t *ips, size_t n) {
    free(ab->bound_ips);
    ab->bound_ips = NULL;
    ab->n_bound = 0;
    ab->cap_bound = 0;
    if (n == 0) return;
    ab->bound_ips = malloc(n * sizeof(*ab->bound_ips));
    if (!ab->bound_ips) return;
    memcpy(ab->bound_ips, ips, n * sizeof(*ab->bound_ips));
    ab->n_bound = n;
    ab->cap_bound = n;
}

/* ----------------------------- ip neigh ------------------------------- */

static int neigh_replace(const wg_arp_bind_t *ab, uint32_t ip,
                         const char *mac_str) {
    char ipbuf[16];
    ip_format(ip, ipbuf);
    char *argv[] = {
        (char*)ab->ip_bin, (char*)"neigh", (char*)"replace",
        ipbuf, (char*)"lladdr", (char*)mac_str,
        (char*)"dev", (char*)ab->iface,
        (char*)"nud", (char*)"permanent",
        NULL
    };
    return run_quiet(ab->ip_bin, argv);
}

static int neigh_del(const wg_arp_bind_t *ab, uint32_t ip) {
    char ipbuf[16];
    ip_format(ip, ipbuf);
    char *argv[] = {
        (char*)ab->ip_bin, (char*)"neigh", (char*)"del",
        ipbuf, (char*)"dev", (char*)ab->iface,
        NULL
    };
    return run_quiet(ab->ip_bin, argv);
}

/* --------------------- interface self-IP lookup ---------------------- */

/* Query the kernel for the primary IPv4 address on `iface`. Returns 0 if
 * no address is assigned (yet) — caller treats that as "don't skip anything
 * in the CIDR loop"; the gateway case is simply not detected. */
static uint32_t lookup_iface_ip(const char *iface) {
    if (!iface || !*iface) return 0;
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 0;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    size_t ifn = strnlen(iface, IFNAMSIZ - 1);
    memcpy(ifr.ifr_name, iface, ifn);
    ifr.ifr_name[ifn] = 0;
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) { close(fd); return 0; }
    close(fd);
    if (ifr.ifr_addr.sa_family != AF_INET) return 0;
    struct sockaddr_in *sa = (struct sockaddr_in *)&ifr.ifr_addr;
    return ntohl(sa->sin_addr.s_addr);
}

/* ------------------------------ init ---------------------------------- */

int arp_bind_init(wg_arp_bind_t *ab, const char *ip_bin,
                  const char *iface, const char *static_cidr) {
    memset(ab, 0, sizeof(*ab));
    if (ip_bin) {
        size_t n = strnlen(ip_bin, sizeof(ab->ip_bin) - 1);
        memcpy(ab->ip_bin, ip_bin, n);
        ab->ip_bin[n] = 0;
    }
    if (iface) {
        size_t n = strnlen(iface, sizeof(ab->iface) - 1);
        memcpy(ab->iface, iface, n);
        ab->iface[n] = 0;
    }
    if (!static_cidr || !*static_cidr) return 0;  /* active stays false */
    if (!cidr_parse(static_cidr, &ab->cidr_addr, &ab->cidr_mask)) {
        LOG_W("arp_bind: invalid WG_STATIC_CIDR=%s; skipping", static_cidr);
        return -1;
    }
    uint32_t lo = ab->cidr_addr;
    uint32_t hi = ab->cidr_addr | ~ab->cidr_mask;
    if (hi <= lo + 1 || (hi - lo - 1) > WG_ARP_MAX_PINS) {
        LOG_W("arp_bind: WG_STATIC_CIDR=%s out of range (max %d hosts); skipping",
              static_cidr, WG_ARP_MAX_PINS);
        return -1;
    }
    ab->self_ip = lookup_iface_ip(ab->iface);
    if (ab->self_ip) {
        char buf[16]; ip_format(ab->self_ip, buf);
        LOG_I("arp_bind: skipping own iface IP %s on %s", buf, ab->iface);
    }
    ab->active = true;
    return 0;
}

/* ------------------------------ apply --------------------------------- */

static void append_u32(uint32_t **arr, size_t *n, size_t *cap, uint32_t v) {
    if (*n == *cap) {
        size_t nc = *cap ? *cap * 2 : 64;
        uint32_t *na = realloc(*arr, nc * sizeof(*na));
        if (!na) return;
        *arr = na;
        *cap = nc;
    }
    (*arr)[(*n)++] = v;
}

void arp_bind_apply(wg_arp_bind_t *ab, const wg_leases_t *leases) {
    if (!ab || !ab->active) return;

    /* Re-query each apply: on boot the iface may not have an IP yet
     * when init ran, and a later SIGHUP is the natural place to pick
     * it up. Cheap ioctl, called a handful of times per day. */
    uint32_t ip_now = lookup_iface_ip(ab->iface);
    if (ip_now && ip_now != ab->self_ip) {
        char buf[16]; ip_format(ip_now, buf);
        LOG_I("arp_bind: iface IP is %s; will skip it", buf);
        ab->self_ip = ip_now;
    }

    /* Build a flat list of (ip, mac_text) pairs we want pinned. */
    typedef struct { uint32_t ip; char mac[18]; } pin_t;
    pin_t *pins = NULL;
    size_t n_pins = 0, cap_pins = 0;

    uint32_t lo = ab->cidr_addr;
    uint32_t hi = ab->cidr_addr | ~ab->cidr_mask;

    /* 1) every IP in the CIDR (except network, broadcast, and our own
     *    iface IP — pinning the gateway to itself is a weird no-op) */
    for (uint32_t ip = lo + 1; ip < hi; ip++) {
        if (ip == ab->self_ip) continue;
        const wg_lease_t *l = leases_by_ip(leases, ip);
        const char *mac_str;
        char macbuf[18];
        if (l && l->is_static) {
            mac_buf(l->mac, macbuf);
            mac_str = macbuf;
        } else {
            mac_str = WG_ARP_DUMMY_MAC;
        }
        if (n_pins == cap_pins) {
            size_t nc = cap_pins ? cap_pins * 2 : 64;
            pin_t *np = realloc(pins, nc * sizeof(*np));
            if (!np) break;
            pins = np;
            cap_pins = nc;
        }
        pins[n_pins].ip = ip;
        memcpy(pins[n_pins].mac, mac_str, strlen(mac_str) + 1);
        n_pins++;
    }

    /* 2) delete stale pins from the previous apply */
    uint32_t *new_ips = NULL;
    size_t    new_n = 0, new_cap = 0;
    for (size_t i = 0; i < n_pins; i++) append_u32(&new_ips, &new_n, &new_cap, pins[i].ip);

    for (size_t i = 0; i < ab->n_bound; i++) {
        uint32_t old = ab->bound_ips[i];
        bool still = false;
        for (size_t k = 0; k < n_pins; k++) {
            if (pins[k].ip == old) { still = true; break; }
        }
        if (!still) neigh_del(ab, old);
    }

    /* 3) install / replace every current pin */
    for (size_t i = 0; i < n_pins; i++) {
        neigh_replace(ab, pins[i].ip, pins[i].mac);
    }

    bound_set_replace(ab, new_ips, new_n);
    free(new_ips);
    free(pins);

    LOG_I("arp_bind: %zu static-zone entries pinned on %s", n_pins, ab->iface);
}

/* ----------------------------- shutdown ------------------------------- */

void arp_bind_shutdown(wg_arp_bind_t *ab) {
    if (!ab || !ab->active) return;
    for (size_t i = 0; i < ab->n_bound; i++) {
        neigh_del(ab, ab->bound_ips[i]);
    }
    free(ab->bound_ips);
    ab->bound_ips = NULL;
    ab->n_bound = 0;
    ab->cap_bound = 0;
}

void arp_bind_free(wg_arp_bind_t *ab) {
    if (!ab) return;
    free(ab->bound_ips);
    memset(ab, 0, sizeof(*ab));
}
