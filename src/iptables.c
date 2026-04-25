#include "iptables.h"
#include "log.h"
#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* Every rule wgatectl writes into FORWARD carries this comment so we can
 * reliably identify and delete our own rules without touching external
 * rules (DOCKER-*, -i wan *, user's custom rules). */
#define WG_COMMENT "wgatectl"

/* --------------------------- exec helper ---------------------------- */

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

/* ------------------------- argv builders ---------------------------- */

#define MAX_ARGV 24

/* argv builder: one NUL-terminated argv array with caller-owned storage
 * for any synthesized strings. */
typedef struct {
    char *argv [MAX_ARGV];
    char *owned[MAX_ARGV];     /* pointers that must be freed */
    size_t n;
    size_t n_owned;
} argv_t;

static void argv_init(argv_t *a) { memset(a, 0, sizeof(*a)); }

static void argv_free(argv_t *a) {
    for (size_t i = 0; i < a->n_owned; i++) free(a->owned[i]);
    memset(a, 0, sizeof(*a));
}

static void argv_push(argv_t *a, const char *s) {
    if (a->n + 1 >= MAX_ARGV) return;
    a->argv[a->n++] = (char*)s;
}

static void argv_terminate(argv_t *a) {
    if (a->n < MAX_ARGV) a->argv[a->n] = NULL;
}

/* Append -A FORWARD with the wgatectl comment followed by the caller's
 * match/target tokens. */
static int append_tagged(const char *bin, const char *const *extra, size_t nextra,
                         int *added) {
    argv_t a; argv_init(&a);
    argv_push(&a, bin);
    argv_push(&a, "-A");
    argv_push(&a, "FORWARD");
    argv_push(&a, "-m"); argv_push(&a, "comment");
    argv_push(&a, "--comment"); argv_push(&a, WG_COMMENT);
    for (size_t i = 0; i < nextra; i++) argv_push(&a, extra[i]);
    argv_terminate(&a);
    int rc = run_iptables(bin, a.argv, NULL, 0, NULL);
    if (rc == 0 && added) (*added)++;
    else if (rc != 0) LOG_W("iptables -A failed rc=%d", rc);
    argv_free(&a);
    return rc;
}

/* ------------------------- line parsing ----------------------------- */

/* Is the given `-A FORWARD …` line one that wgatectl is responsible for? */
static bool line_is_ours(const char *line, uint32_t net_addr, uint32_t net_mask) {
    /* tagged rules */
    if (strstr(line, "--comment " WG_COMMENT)) return true;
    /* legacy wgate_* match-set rules (pre-comment-tag) */
    if (strstr(line, "--match-set wgate_")) return true;
    /* legacy `-A FORWARD -s <LAN-IP>[/32] -j DROP` (no comment) — these
     * came from the now-removed per-host blocks subsystem; clean them up
     * for one release after upgrade so they don't linger. */
    if (strstr(line, " -j DROP") && strstr(line, " -s ")) {
        const char *s = strstr(line, " -s ");
        if (s) {
            s += 4;
            char ipbuf[24];
            size_t n = 0;
            while (s[n] && s[n] != ' ' && s[n] != '/' && n < sizeof(ipbuf) - 1) {
                ipbuf[n] = s[n];
                n++;
            }
            ipbuf[n] = 0;
            uint32_t ip;
            if (ip_parse(ipbuf, &ip) && ip_in_subnet(ip, net_addr, net_mask))
                return true;
        }
    }
    return false;
}

/* Tokenise one `-A FORWARD …` line into an argv where the first token is
 * rewritten from `-A` to `-D`. The argv entries point into `line_copy`,
 * which the caller owns. Returns argv (NUL-terminated) or NULL on error.
 * The NUL-terminated argv has `bin` injected at argv[0]. */
static int build_delete_argv(const char *bin, char *line_copy, argv_t *out) {
    argv_init(out);
    argv_push(out, bin);
    /* tokenise on whitespace; no quoting since our rules contain no
     * spaces inside a single token */
    char *saveptr = NULL;
    char *tok = strtok_r(line_copy, " \t\r\n", &saveptr);
    bool first = true;
    while (tok) {
        if (first) {
            first = false;
            if (strcmp(tok, "-A") != 0) return -1;
            argv_push(out, "-D");
        } else {
            argv_push(out, tok);
        }
        tok = strtok_r(NULL, " \t\r\n", &saveptr);
    }
    argv_terminate(out);
    /* sanity: at least `bin -D FORWARD`, i.e. >= 3 argv entries */
    if (out->n < 3) return -1;
    return 0;
}

/* --------------------------- reconcile ------------------------------ */

/* FNV-1a 64. Used only for the desired-state cache; not security-sensitive. */
static uint64_t fnv1a64(const void *buf, size_t n, uint64_t hash) {
    const uint8_t *p = buf;
    for (size_t i = 0; i < n; i++) {
        hash ^= p[i];
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

/* Hash everything that affects the rules pass 2 emits, so that an
 * identical desired state collapses to a no-op in iptables_reconcile.
 * Per-host pin/block state is realised in ipsets, not in FORWARD rules,
 * so the signature only needs to track the iface/cidr/network/mode tuple
 * — those fully determine the rule list. */
static uint64_t compute_desired_sig(const char *lan_iface,
                                    const char *static_cidr,
                                    uint32_t net_addr, uint32_t net_mask,
                                    bool closed_mode, bool filtered_mode) {
    uint64_t h = 0xcbf29ce484222325ULL;
    uint8_t flags = (uint8_t)((closed_mode ? 1 : 0) | (filtered_mode ? 2 : 0));
    h = fnv1a64(&flags, 1, h);
    if (lan_iface)   h = fnv1a64(lan_iface,   strlen(lan_iface),   h);
    h = fnv1a64("|", 1, h);
    if (static_cidr) h = fnv1a64(static_cidr, strlen(static_cidr), h);
    h = fnv1a64("|", 1, h);
    h = fnv1a64(&net_addr, sizeof(net_addr), h);
    h = fnv1a64(&net_mask, sizeof(net_mask), h);
    return h;
}

int iptables_reconcile(wg_iptables_t *t,
                       const char *lan_iface,
                       const char *static_cidr,
                       uint32_t net_addr, uint32_t net_mask,
                       bool closed_mode,
                       bool filtered_mode) {
    const char *bin = t->iptables_bin;

    /* Skip the entire fork-iptables-S + delete + re-append dance when the
     * desired state matches what we last applied. Trade-off: external
     * tampering (someone manually flushes our rules) won't auto-heal
     * until the next real change — acceptable on a single-tenant
     * gateway, and worth it to keep the log free of per-minute +N -N
     * noise that buries actual state changes. */
    uint64_t sig = compute_desired_sig(lan_iface, static_cidr,
                                       net_addr, net_mask,
                                       closed_mode, filtered_mode);
    if (t->have_last_sig && sig == t->last_sig) return 0;

    /* --- pass 1: list FORWARD and delete every rule that's ours --- */
    static char buf[128 * 1024];
    size_t nb = 0;
    char *ls[] = { (char*)bin, (char*)"-S", (char*)"FORWARD", NULL };
    int rc = run_iptables(bin, ls, buf, sizeof(buf), &nb);
    if (rc != 0) {
        LOG_W("iptables -S FORWARD: rc=%d", rc);
        return -1;
    }

    int na = 0, nr = 0;

    char *p = buf;
    while (*p) {
        char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);

        if (len > 10 && strncmp(p, "-A FORWARD", 10) == 0) {
            char line_nul[1024];
            size_t take = len < sizeof(line_nul) ? len : sizeof(line_nul) - 1;
            memcpy(line_nul, p, take);
            line_nul[take] = 0;

            if (line_is_ours(line_nul, net_addr, net_mask)) {
                /* tokenise a separate copy so the `line_is_ours` pointer
                 * stays valid for diagnostics if ever needed */
                char tok_copy[1024];
                memcpy(tok_copy, line_nul, take);
                tok_copy[take] = 0;

                argv_t del;
                if (build_delete_argv(bin, tok_copy, &del) == 0) {
                    int drc = run_iptables(bin, del.argv, NULL, 0, NULL);
                    if (drc == 0) nr++;
                    else LOG_W("iptables -D failed (rc=%d): %s", drc, line_nul);
                }
            }
        }

        if (!nl) break;
        p = nl + 1;
    }

    /* --- pass 2: append the fresh block in the desired order --- */

    bool have_lan = lan_iface && *lan_iface;

    /* rule 1: captive-check whitelist (per dst). The src direction is
     * intentionally NOT emitted — return traffic comes back via the WAN
     * iface and is allowed by FORWARD's default-ACCEPT policy. */
    if (have_lan) {
        const char *r1[] = {
            "-i", lan_iface,
            "-m", "set", "--match-set", "wgate_allow", "dst",
            "-j", "ACCEPT"
        };
        append_tagged(bin, r1, sizeof(r1)/sizeof(*r1), &na);
    }

    /* rule 2: static-zone exempt */
    if (static_cidr && *static_cidr) {
        const char *r2[] = { "-s", static_cidr, "-j", "ACCEPT" };
        append_tagged(bin, r2, sizeof(r2)/sizeof(*r2), &na);
    }

    /* rules 3-6: per-host pin overrides — these short-circuit the
     * global mode for hosts whose IP appears in a wgate_pin_* set. */
    if (have_lan) {
        /* rule 3: pin → open, accept */
        const char *r3[] = {
            "-i", lan_iface,
            "-m", "set", "--match-set", "wgate_pin_open", "src",
            "-j", "ACCEPT"
        };
        append_tagged(bin, r3, sizeof(r3)/sizeof(*r3), &na);

        /* rule 4: pin → closed, drop */
        const char *r4[] = {
            "-i", lan_iface,
            "-m", "set", "--match-set", "wgate_pin_closed", "src",
            "-j", "DROP"
        };
        append_tagged(bin, r4, sizeof(r4)/sizeof(*r4), &na);

        /* rule 5: pin → filtered + filterd dst → drop (filter the
         * matched domains for pinned-filtered hosts). */
        const char *r5[] = {
            "-i", lan_iface,
            "-m", "set", "--match-set", "wgate_pin_filt", "src",
            "-m", "set", "--match-set", "wgate_filterd",  "dst",
            "-j", "DROP"
        };
        append_tagged(bin, r5, sizeof(r5)/sizeof(*r5), &na);

        /* rule 6: pin → filtered, accept the rest (so the global mode
         * doesn't subsequently drop them in closed/filtered mode). */
        const char *r6[] = {
            "-i", lan_iface,
            "-m", "set", "--match-set", "wgate_pin_filt", "src",
            "-j", "ACCEPT"
        };
        append_tagged(bin, r6, sizeof(r6)/sizeof(*r6), &na);
    }

    /* rule 7: global-mode tail */
    if (have_lan) {
        if (closed_mode) {
            const char *r7[] = { "-i", lan_iface, "-j", "DROP" };
            append_tagged(bin, r7, sizeof(r7)/sizeof(*r7), &na);
        } else if (filtered_mode) {
            const char *r7[] = {
                "-i", lan_iface,
                "-m", "set", "--match-set", "wgate_filterd", "dst",
                "-j", "DROP"
            };
            append_tagged(bin, r7, sizeof(r7)/sizeof(*r7), &na);
        }
        /* open: no rule 7 */
    }
    /* No trailing catch-all ACCEPT: FORWARD's policy is ACCEPT by
     * default, so anything that falls off the end is already allowed.
     * Appending one would short-circuit admin-added DROP rules placed
     * after ours. */

    const char *mode_name = closed_mode   ? "closed"
                          : filtered_mode ? "filtered"
                          :                 "open";
    if (na || nr)
        LOG_I("iptables: +%d -%d (mode=%s)", na, nr, mode_name);
    t->last_sig      = sig;
    t->have_last_sig = true;
    return 0;
}
