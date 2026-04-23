#include "iptables.h"
#include "log.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

void wg_block_set_init(wg_block_set_t *b) { memset(b, 0, sizeof(*b)); }
void wg_block_set_free(wg_block_set_t *b) { free(b->blocked_ips); memset(b, 0, sizeof(*b)); }

void wg_block_set_add(wg_block_set_t *b, uint32_t ip) {
    for (size_t i = 0; i < b->n; i++) if (b->blocked_ips[i] == ip) return;
    if (b->n == b->cap) {
        size_t ncap = b->cap ? b->cap * 2 : 32;
        uint32_t *ni = realloc(b->blocked_ips, ncap * sizeof(*ni));
        if (!ni) return;
        b->blocked_ips = ni;
        b->cap = ncap;
    }
    b->blocked_ips[b->n++] = ip;
}

bool wg_block_set_has(const wg_block_set_t *b, uint32_t ip) {
    for (size_t i = 0; i < b->n; i++) if (b->blocked_ips[i] == ip) return true;
    return false;
}

/* Run iptables with argv (NULL-terminated). Returns status (0 ok, non-0 fail).
 * If `capture` is non-NULL and `capcap` > 0, stdout is read into `capture`
 * up to capcap-1 bytes and NUL-terminated; returns read bytes in *out_cap. */
static int run_iptables(const char *bin, char *const argv[],
                        char *capture, size_t capcap, size_t *out_cap) {
    int pipefd[2] = { -1, -1 };
    if (capture && pipe2(pipefd, O_CLOEXEC) < 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        if (pipefd[0] >= 0) { close(pipefd[0]); close(pipefd[1]); }
        return -1;
    }
    if (pid == 0) {
        if (capture) {
            dup2(pipefd[1], 1);
            close(pipefd[0]);
            close(pipefd[1]);
        } else {
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) { dup2(devnull, 1); if (devnull > 2) close(devnull); }
        }
        /* Leave stderr attached — iptables's own diagnostics go to the
         * journal, which is the only way to know *why* a rule failed. */
        execv(bin, argv);
        _exit(127);
    }

    if (capture) close(pipefd[1]);
    size_t read_bytes = 0;
    if (capture) {
        while (read_bytes + 1 < capcap) {
            ssize_t r = read(pipefd[0], capture + read_bytes, capcap - 1 - read_bytes);
            if (r < 0) { if (errno == EINTR) continue; break; }
            if (r == 0) break;
            read_bytes += (size_t)r;
        }
        /* drain rest */
        char sink[512];
        while (read_bytes + 1 >= capcap) {
            ssize_t r = read(pipefd[0], sink, sizeof(sink));
            if (r <= 0) break;
        }
        capture[read_bytes] = 0;
        close(pipefd[0]);
    }
    if (out_cap) *out_cap = read_bytes;

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) { /* retry on EINTR */ }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
}

int iptables_bootstrap(wg_iptables_t *t, const char *ipset_bin_for_match) {
    (void)ipset_bin_for_match;  /* unused, kept for API symmetry */
    /* Ensure ACCEPT-by-ipset rules are present at slots 1-2. We use -C to
     * detect; if absent, -I at the appropriate position. */
    struct {
        const char *dir;  /* "dst" or "src" */
        int         pos;
    } rules[] = { { "dst", 1 }, { "src", 2 } };

    for (int i = 0; i < 2; i++) {
        /* check */
        char *chk[] = {
            (char*)t->iptables_bin, (char*)"-C", (char*)"FORWARD",
            (char*)"-m", (char*)"set", (char*)"--match-set",
            (char*)"wgate_allow", (char*)rules[i].dir, (char*)"-j",
            (char*)"ACCEPT", NULL
        };
        if (run_iptables(t->iptables_bin, chk, NULL, 0, NULL) == 0) continue;
        /* insert */
        char pos_buf[8];
        snprintf(pos_buf, sizeof(pos_buf), "%d", rules[i].pos);
        char *ins[] = {
            (char*)t->iptables_bin, (char*)"-I", (char*)"FORWARD",
            pos_buf, (char*)"-m", (char*)"set", (char*)"--match-set",
            (char*)"wgate_allow", (char*)rules[i].dir, (char*)"-j",
            (char*)"ACCEPT", NULL
        };
        int rc = run_iptables(t->iptables_bin, ins, NULL, 0, NULL);
        if (rc != 0) LOG_W("iptables insert ACCEPT %s: rc=%d", rules[i].dir, rc);
        else         LOG_I("iptables: inserted ACCEPT (wgate_allow %s) at FORWARD slot %d",
                           rules[i].dir, rules[i].pos);
    }
    return 0;
}

int iptables_drop_add(wg_iptables_t *t, uint32_t ip) {
    char ipbuf[16];
    ip_format(ip, ipbuf);
    char *argv[] = {
        (char*)t->iptables_bin, (char*)"-A", (char*)"FORWARD",
        (char*)"-s", ipbuf, (char*)"-j", (char*)"DROP", NULL
    };
    return run_iptables(t->iptables_bin, argv, NULL, 0, NULL);
}

int iptables_drop_remove(wg_iptables_t *t, uint32_t ip) {
    char ipbuf[16];
    ip_format(ip, ipbuf);
    char *argv[] = {
        (char*)t->iptables_bin, (char*)"-D", (char*)"FORWARD",
        (char*)"-s", ipbuf, (char*)"-j", (char*)"DROP", NULL
    };
    return run_iptables(t->iptables_bin, argv, NULL, 0, NULL);
}

/* Parse `iptables -S FORWARD` output and collect source IPs of any
 *   -A FORWARD -s X -j DROP
 * rule (where X is in our LAN). */
static void parse_drop_sources(const char *text, uint32_t net_addr,
                               uint32_t net_mask, wg_block_set_t *out) {
    const char *p = text;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);

        /* Expect lines like "-A FORWARD -s 10.6.6.X/32 -j DROP" */
        if (len > 6 && strncmp(p, "-A FORWARD", 10) == 0) {
            const char *s = memmem(p, len, " -s ", 4);
            const char *j = memmem(p, len, " -j DROP", 8);
            if (s && j && j > s) {
                s += 4;
                const char *e = s;
                while (e < p + len && *e != ' ' && *e != '/') e++;
                char ipbuf[24];
                size_t nn = (size_t)(e - s);
                if (nn > 0 && nn < sizeof(ipbuf)) {
                    memcpy(ipbuf, s, nn);
                    ipbuf[nn] = 0;
                    uint32_t ip;
                    if (ip_parse(ipbuf, &ip) && ip_in_subnet(ip, net_addr, net_mask))
                        wg_block_set_add(out, ip);
                }
            }
        }
        if (!nl) break;
        p = nl + 1;
    }
}

int iptables_reconcile(wg_iptables_t *t,
                       uint32_t net_addr, uint32_t net_mask,
                       const wg_block_set_t *desired,
                       int *added, int *removed) {
    /* Always repair the ACCEPT rules first. */
    iptables_bootstrap(t, NULL);

    char buf[65536];
    size_t nb = 0;
    char *argv[] = {
        (char*)t->iptables_bin, (char*)"-S", (char*)"FORWARD", NULL
    };
    int rc = run_iptables(t->iptables_bin, argv, buf, sizeof(buf), &nb);
    if (rc != 0) {
        LOG_W("iptables -S FORWARD: rc=%d", rc);
        return -1;
    }

    wg_block_set_t actual;
    wg_block_set_init(&actual);
    parse_drop_sources(buf, net_addr, net_mask, &actual);

    int na = 0, nr = 0;

    /* add any desired-but-not-actual */
    for (size_t i = 0; i < desired->n; i++) {
        uint32_t ip = desired->blocked_ips[i];
        if (!ip_in_subnet(ip, net_addr, net_mask)) continue;
        if (wg_block_set_has(&actual, ip)) continue;
        if (iptables_drop_add(t, ip) == 0) na++;
    }
    /* remove any actual-but-not-desired inside our LAN */
    for (size_t i = 0; i < actual.n; i++) {
        uint32_t ip = actual.blocked_ips[i];
        if (wg_block_set_has(desired, ip)) continue;
        if (iptables_drop_remove(t, ip) == 0) nr++;
    }

    wg_block_set_free(&actual);
    if (added)   *added   = na;
    if (removed) *removed = nr;
    if (na || nr)
        LOG_I("reconcile: +%d -%d DROP rules", na, nr);
    return 0;
}
