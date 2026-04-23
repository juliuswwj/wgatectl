#include "config.h"
#include "log.h"
#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void set_str(char *dst, size_t cap, const char *src) {
    if (!src) return;
    size_t n = strlen(src);
    if (n >= cap) n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = 0;
}

static void set_int(int *dst, const char *src) {
    if (!src || !*src) return;
    char *endp = NULL;
    long v = strtol(src, &endp, 10);
    if (endp && *endp == 0) *dst = (int)v;
}

static void defaults(wg_cfg_t *c) {
    memset(c, 0, sizeof(*c));
    set_str(c->iface,          sizeof(c->iface),          "eth1");
    set_str(c->network_cidr,   sizeof(c->network_cidr),   "10.6.6.0/24");
    set_str(c->dnsmasq_conf,   sizeof(c->dnsmasq_conf),   "/etc/dnsmasq.conf");
    set_str(c->dnsmasq_leases, sizeof(c->dnsmasq_leases), "/var/lib/misc/dnsmasq.leases");
    set_str(c->blocks_json,    sizeof(c->blocks_json),    "/opt/wgatectl/blocks.json");
    set_str(c->schedule_json,  sizeof(c->schedule_json),  "/opt/wgatectl/schedule.json");
    set_str(c->supervised_json,sizeof(c->supervised_json),"/opt/wgatectl/supervised.json");
    set_str(c->grants_json,    sizeof(c->grants_json),    "/opt/wgatectl/grants.json");
    set_str(c->triggers_json,  sizeof(c->triggers_json),  "/opt/wgatectl/triggers.json");
    set_str(c->jsonl_dir,      sizeof(c->jsonl_dir),      "/opt/wgatectl");
    c->jsonl_retain_days = 14;
    set_str(c->sock_path,      sizeof(c->sock_path),      "/opt/wgatectl/wgatectl.sock");
    set_str(c->sock_group,     sizeof(c->sock_group),     "wgate");
    set_str(c->iptables_bin,   sizeof(c->iptables_bin),   "/sbin/iptables");
    set_str(c->ipset_bin,      sizeof(c->ipset_bin),      "/sbin/ipset");
    set_str(c->ip_bin,         sizeof(c->ip_bin),         "/sbin/ip");
    c->static_cidr[0] = 0;
    c->flush_seconds = 60;
    c->supervised_threshold_min      = 5;
    c->supervised_cooldown_min       = 60;
    c->supervised_min_bytes_per_min  = 32 * 1024;   /* 32 KiB / min */
}

static void apply_kv(wg_cfg_t *c, const char *k, const char *v) {
    if      (!strcmp(k, "WG_IFACE"))           set_str(c->iface,          sizeof(c->iface),          v);
    else if (!strcmp(k, "WG_NETWORK"))         set_str(c->network_cidr,   sizeof(c->network_cidr),   v);
    else if (!strcmp(k, "WG_DNSMASQ_CONF"))    set_str(c->dnsmasq_conf,   sizeof(c->dnsmasq_conf),   v);
    else if (!strcmp(k, "WG_DNSMASQ_LEASES"))  set_str(c->dnsmasq_leases, sizeof(c->dnsmasq_leases), v);
    else if (!strcmp(k, "WG_BLOCKS_JSON"))     set_str(c->blocks_json,    sizeof(c->blocks_json),    v);
    else if (!strcmp(k, "WG_SCHEDULE_JSON"))   set_str(c->schedule_json,  sizeof(c->schedule_json),  v);
    else if (!strcmp(k, "WG_SUPERVISED_JSON")) set_str(c->supervised_json,sizeof(c->supervised_json),v);
    else if (!strcmp(k, "WG_GRANTS_JSON"))     set_str(c->grants_json,    sizeof(c->grants_json),    v);
    else if (!strcmp(k, "WG_TRIGGERS_JSON"))   set_str(c->triggers_json,  sizeof(c->triggers_json),  v);
    else if (!strcmp(k, "WG_JSONL_DIR"))       set_str(c->jsonl_dir,      sizeof(c->jsonl_dir),      v);
    else if (!strcmp(k, "WG_JSONL_RETAIN"))    set_int(&c->jsonl_retain_days, v);
    else if (!strcmp(k, "WG_SOCK"))            set_str(c->sock_path,      sizeof(c->sock_path),      v);
    else if (!strcmp(k, "WG_SOCK_GROUP"))      set_str(c->sock_group,     sizeof(c->sock_group),     v);
    else if (!strcmp(k, "WG_IPTABLES_BIN"))    set_str(c->iptables_bin,   sizeof(c->iptables_bin),   v);
    else if (!strcmp(k, "WG_IPSET_BIN"))       set_str(c->ipset_bin,      sizeof(c->ipset_bin),      v);
    else if (!strcmp(k, "WG_IP_BIN"))          set_str(c->ip_bin,         sizeof(c->ip_bin),         v);
    else if (!strcmp(k, "WG_STATIC_CIDR"))     set_str(c->static_cidr,    sizeof(c->static_cidr),    v);
    else if (!strcmp(k, "WG_FLUSH_SECONDS"))   set_int(&c->flush_seconds, v);
    else if (!strcmp(k, "WG_SUPERVISED_THRESHOLD_MIN")) set_int(&c->supervised_threshold_min, v);
    else if (!strcmp(k, "WG_SUPERVISED_COOLDOWN_MIN"))  set_int(&c->supervised_cooldown_min,  v);
    else if (!strcmp(k, "WG_SUPERVISED_MIN_BYTES_PER_MIN")) set_int(&c->supervised_min_bytes_per_min, v);
}

static char *trim(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) *--end = 0;
    return s;
}

static int load_file(wg_cfg_t *c, const char *path) {
    size_t n = 0;
    char *buf = read_small_file(path, 16 * 1024, &n);
    if (!buf) return -1;
    char *line = buf;
    while (*line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        char *s = trim(line);
        if (*s && *s != '#') {
            char *eq = strchr(s, '=');
            if (eq) {
                *eq = 0;
                char *k = trim(s);
                char *v = trim(eq + 1);
                apply_kv(c, k, v);
            }
        }
        if (!nl) break;
        line = nl + 1;
    }
    free(buf);
    return 0;
}

static void load_env(wg_cfg_t *c) {
    static const char *keys[] = {
        "WG_IFACE", "WG_NETWORK",
        "WG_DNSMASQ_CONF", "WG_DNSMASQ_LEASES", "WG_BLOCKS_JSON",
        "WG_SCHEDULE_JSON", "WG_SUPERVISED_JSON",
        "WG_GRANTS_JSON", "WG_TRIGGERS_JSON",
        "WG_JSONL_DIR", "WG_JSONL_RETAIN",
        "WG_SOCK", "WG_SOCK_GROUP",
        "WG_IPTABLES_BIN", "WG_IPSET_BIN", "WG_IP_BIN", "WG_STATIC_CIDR",
        "WG_FLUSH_SECONDS",
        "WG_SUPERVISED_THRESHOLD_MIN", "WG_SUPERVISED_COOLDOWN_MIN",
        "WG_SUPERVISED_MIN_BYTES_PER_MIN",
        NULL
    };
    for (int i = 0; keys[i]; i++) {
        const char *v = getenv(keys[i]);
        if (v) apply_kv(c, keys[i], v);
    }
}

int cfg_load(wg_cfg_t *cfg, const char *conf_path_or_null) {
    defaults(cfg);
    const char *conf = conf_path_or_null ? conf_path_or_null : "/etc/wgatectl.conf";
    if (load_file(cfg, conf) < 0) {
        LOG_E("cannot open config %s: %s", conf, strerror(errno));
        return -1;
    }
    load_env(cfg);

    if (!cidr_parse(cfg->network_cidr, &cfg->net_addr, &cfg->net_mask)) {
        LOG_E("invalid network CIDR: %s", cfg->network_cidr);
        return -1;
    }
    if (cfg->flush_seconds < 10)  cfg->flush_seconds = 10;
    if (cfg->flush_seconds > 600) cfg->flush_seconds = 600;
    if (cfg->supervised_threshold_min < 1)   cfg->supervised_threshold_min = 1;
    if (cfg->supervised_threshold_min > 120) cfg->supervised_threshold_min = 120;
    if (cfg->supervised_cooldown_min  < 1)        cfg->supervised_cooldown_min = 1;
    if (cfg->supervised_cooldown_min  > 24 * 60)  cfg->supervised_cooldown_min = 24 * 60;
    if (cfg->supervised_min_bytes_per_min < 0)    cfg->supervised_min_bytes_per_min = 0;

    /* Resolve external binaries. We search standard locations if the
     * configured path doesn't exist, so users don't hit cryptic rc=127
     * errors on distros where /sbin and /usr/sbin are merged or split. */
    char found[256];
    if (!resolve_bin(cfg->iptables_bin, "iptables", found, sizeof(found))) {
        LOG_E("iptables binary not found (hint=%s); install iptables",
              cfg->iptables_bin);
        return -1;
    }
    set_str(cfg->iptables_bin, sizeof(cfg->iptables_bin), found);

    if (!resolve_bin(cfg->ipset_bin, "ipset", found, sizeof(found))) {
        LOG_E("ipset binary not found (hint=%s); install ipset "
              "(apt install ipset) or set WG_IPSET_BIN", cfg->ipset_bin);
        return -1;
    }
    set_str(cfg->ipset_bin, sizeof(cfg->ipset_bin), found);

    if (!resolve_bin(cfg->ip_bin, "ip", found, sizeof(found))) {
        LOG_E("ip binary not found (hint=%s); install iproute2 "
              "or set WG_IP_BIN", cfg->ip_bin);
        return -1;
    }
    set_str(cfg->ip_bin, sizeof(cfg->ip_bin), found);

    LOG_I("binaries: iptables=%s ipset=%s ip=%s",
          cfg->iptables_bin, cfg->ipset_bin, cfg->ip_bin);
    return 0;
}
