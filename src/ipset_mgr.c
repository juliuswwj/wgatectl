#include "ipset_mgr.h"
#include "log.h"
#include "util.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define LRU_SIZE 4096

struct ipset_mgr {
    char     ipset_bin[96];
    uint32_t lru[LRU_SIZE];  /* 0 = empty slot */
};

static const char *const g_whitelist[] = {
    "connectivitycheck.gstatic.com",
    "captive.apple.com",
    "www.apple.com",
    "www.msftconnecttest.com",
    "dns.msftncsi.com",
    "www.msftncsi.com",
    "connectivitycheck.platform.hicloud.com",
    "connect.rom.miui.com",
    "connectivity-check.ubuntu.com",
    "nmcheck.gnome.org",
    NULL
};

const char *const *ipset_mgr_whitelist_fqdns(void) {
    return g_whitelist;
}

static int run_ipset(const char *bin, char *const argv[]) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        /* Silence stdout only; keep stderr so ipset's own error messages
         * reach the journal. */
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, 1);
            if (devnull > 2) close(devnull);
        }
        execv(bin, argv);
        _exit(127);
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) { /* retry on EINTR */ }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
}

/* Create+flush a single hash:ip set with the given timeout. */
static void ensure_set(const char *bin, const char *name, const char *timeout) {
    {
        char *argv[] = {
            (char*)bin, (char*)"create", (char*)name, (char*)"hash:ip",
            (char*)"timeout", (char*)timeout, (char*)"-exist", NULL
        };
        int rc = run_ipset(bin, argv);
        if (rc != 0) LOG_W("ipset create %s: rc=%d", name, rc);
    }
    {
        char *argv[] = {
            (char*)bin, (char*)"flush", (char*)name, NULL
        };
        int rc = run_ipset(bin, argv);
        if (rc != 0) LOG_W("ipset flush %s: rc=%d", name, rc);
    }
}

ipset_mgr_t *ipset_mgr_new(const char *ipset_bin) {
    ipset_mgr_t *m = calloc(1, sizeof(*m));
    if (!m) return NULL;
    strncpy(m->ipset_bin, ipset_bin, sizeof(m->ipset_bin) - 1);

    ensure_set(m->ipset_bin, "wgate_allow",      "0");
    /* wgate_filterd entries age out after 10 min if a domain stops
     * being resolved — see filterd.c FILTERD_TIMEOUT_S. */
    ensure_set(m->ipset_bin, "wgate_filterd",    "600");
    /* pin sets: managed by pins_dump_to_ipsets which flushes+repopulates
     * each minute, so no kernel-side timeout is needed. */
    ensure_set(m->ipset_bin, "wgate_pin_open",   "0");
    ensure_set(m->ipset_bin, "wgate_pin_closed", "0");
    ensure_set(m->ipset_bin, "wgate_pin_filt",   "0");

    LOG_I("ipset: wgate_allow / wgate_filterd / wgate_pin_{open,closed,filt} ready");
    return m;
}

static bool lru_seen(ipset_mgr_t *m, uint32_t ip) {
    /* Direct-mapped cache with linear-probe insert on collision. */
    size_t i = (size_t)(ip * 2654435761u) & (LRU_SIZE - 1);
    for (size_t k = 0; k < 8; k++) {
        size_t p = (i + k) & (LRU_SIZE - 1);
        if (m->lru[p] == ip) return true;
        if (m->lru[p] == 0)  { m->lru[p] = ip; return false; }
    }
    /* Evict slot i. */
    m->lru[i] = ip;
    return false;
}

int ipset_mgr_add(ipset_mgr_t *m, uint32_t ip) {
    if (!m || ip == 0) return 0;
    if (lru_seen(m, ip)) return 0;
    char ipbuf[16];
    ip_format(ip, ipbuf);
    char *argv[] = {
        (char*)m->ipset_bin, (char*)"add", (char*)"wgate_allow",
        ipbuf, (char*)"-exist", NULL
    };
    int rc = run_ipset(m->ipset_bin, argv);
    if (rc != 0) LOG_W("ipset add %s: rc=%d", ipbuf, rc);
    return rc;
}

bool ipset_mgr_is_whitelist_fqdn(const char *qname) {
    if (!qname) return false;
    size_t qn = strlen(qname);
    for (const char *const *p = g_whitelist; *p; p++) {
        size_t pn = strlen(*p);
        if (pn == qn) {
            if (strcasecmp(qname, *p) == 0) return true;
        } else if (qn > pn + 1) {
            if (qname[qn - pn - 1] == '.' &&
                strcasecmp(qname + qn - pn, *p) == 0) return true;
        }
    }
    return false;
}

void ipset_mgr_free(ipset_mgr_t *m) {
    free(m);
}
