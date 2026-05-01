#include "leases.h"
#include "log.h"
#include "seen_db.h"
#include "util.h"

/* During loading, is_static is used as a transient "came from dhcp-host="
 * flag so add() can prefer dnsmasq.conf entries over leases-file entries
 * when both describe the same IP. After both sources are parsed,
 * leases_reload() rewrites is_static to its public meaning: "IP lies
 * inside WG_STATIC_CIDR". */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The diff state and seen-db hook live in a sidecar struct so that adding
 * fields here doesn't break call sites that allocate wg_leases_t on the
 * stack and zero-init it. NULL is a valid state ("no diff/seen tracking"). */
typedef struct {
    uint8_t  mac[6];
    uint32_t ip;
    char     name[64];
} dyn_entry_t;

typedef struct {
    dyn_entry_t *prev;
    size_t       n_prev;
    size_t       cap_prev;
    dyn_entry_t *cur;
    size_t       n_cur;
    size_t       cap_cur;
    /* True once at least one leases_reload has populated prev. Used
     * to suppress the diff on the very first reload — every active
     * lease at startup would otherwise look like an "add". */
    bool         prev_seeded;

    wg_seen_db_t        *seen;
    wg_lease_change_cb_t cb;
    void                *cb_arg;
} sidecar_t;

/* Sidecar storage: keyed by leases-table address. We only have one
 * leases table per daemon, so a single-slot lookup suffices. */
static struct {
    const wg_leases_t *owner;
    sidecar_t          sc;
} g_side;

static sidecar_t *side_for(const wg_leases_t *t) {
    if (!t) return NULL;
    if (g_side.owner == t) return &g_side.sc;
    return NULL;
}

static sidecar_t *side_ensure(const wg_leases_t *t) {
    if (g_side.owner && g_side.owner != t) {
        /* leases tables aren't expected to multi-instance; warn and reset. */
        LOG_W("leases: sidecar reassigned (was %p, now %p)",
              (void *)g_side.owner, (void *)t);
        free(g_side.sc.prev); free(g_side.sc.cur);
        memset(&g_side, 0, sizeof(g_side));
    }
    g_side.owner = t;
    return &g_side.sc;
}

void leases_init(wg_leases_t *t) {
    memset(t, 0, sizeof(*t));
}

void leases_free(wg_leases_t *t) {
    free(t->items);
    memset(t, 0, sizeof(*t));
    if (g_side.owner == t) {
        free(g_side.sc.prev);
        free(g_side.sc.cur);
        memset(&g_side, 0, sizeof(g_side));
    }
}

void leases_set_seen_db(wg_leases_t *t, wg_seen_db_t *db) {
    sidecar_t *sc = side_ensure(t);
    sc->seen = db;
}

void leases_set_change_cb(wg_leases_t *t,
                          wg_lease_change_cb_t cb, void *arg) {
    sidecar_t *sc = side_ensure(t);
    sc->cb     = cb;
    sc->cb_arg = arg;
}

static void add(wg_leases_t *t, const wg_lease_t *l) {
    /* Upsert by IP so that a later source (leases file) doesn't duplicate a
     * static dhcp-host entry. */
    for (size_t i = 0; i < t->n; i++) {
        if (t->items[i].ip == l->ip) {
            /* Keep is_static if we already have it static; update name/mac.
             * in_lease_file is sticky-true: a static entry that's also
             * currently leasing should still count as "in the lease file". */
            bool prev_in_lf = t->items[i].in_lease_file;
            if (!t->items[i].is_static) t->items[i] = *l;
            else if (l->name[0] && !t->items[i].name[0])
                strncpy(t->items[i].name, l->name, sizeof(t->items[i].name) - 1);
            t->items[i].in_lease_file = prev_in_lf || l->in_lease_file;
            return;
        }
    }
    if (t->n == t->cap) {
        size_t ncap = t->cap ? t->cap * 2 : 32;
        wg_lease_t *ni = realloc(t->items, ncap * sizeof(*ni));
        if (!ni) return;
        t->items = ni;
        t->cap   = ncap;
    }
    t->items[t->n++] = *l;
}

static char *trim(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    char *e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1])) *--e = 0;
    return s;
}

/* Split a line on any of ",=" into up to `max` fields (in-place). */
static int split_commas(char *s, char **out, int max) {
    int n = 0;
    char *p = s;
    while (n < max) {
        out[n++] = p;
        char *c = p;
        while (*c && *c != ',' && *c != '=') c++;
        if (!*c) break;
        *c = 0;
        p = c + 1;
    }
    return n;
}

static void parse_conf(wg_leases_t *t, const char *path) {
    size_t nbytes = 0;
    char *buf = read_small_file(path, 512 * 1024, &nbytes);
    if (!buf) {
        LOG_W("leases: cannot read %s (%s)", path, "open failed");
        return;
    }
    char *line = buf;
    while (*line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        char *s = trim(line);
        if (*s && *s != '#') {
            if (strncmp(s, "dhcp-host=", 10) == 0) {
                char *fields[8];
                char *rest = s + 10;
                int n = split_commas(rest, fields, 8);
                if (n >= 3) {
                    wg_lease_t l;
                    memset(&l, 0, sizeof(l));
                    uint8_t mac[6];
                    uint32_t ip = 0;
                    int have_mac = 0, have_ip = 0;
                    const char *name = NULL;
                    /* Fields may be in any order among MAC, IP, NAME,
                     * with a possible trailing lease time. */
                    for (int i = 0; i < n; i++) {
                        char *f = trim(fields[i]);
                        if (!*f) continue;
                        if (!have_mac && mac_parse(f, mac)) { have_mac = 1; continue; }
                        if (!have_ip  && ip_parse (f, &ip)) { have_ip  = 1; continue; }
                        if (!name) name = f;
                    }
                    if (have_ip) {
                        l.ip = ip;
                        if (have_mac) memcpy(l.mac, mac, 6);
                        if (name) {
                            strncpy(l.name, name, sizeof(l.name) - 1);
                            l.name[sizeof(l.name) - 1] = 0;
                        }
                        l.is_static = true;
                        add(t, &l);
                    }
                }
            } else if (strncmp(s, "dhcp-range=", 11) == 0) {
                char *fields[8];
                char *rest = s + 11;
                int n = split_commas(rest, fields, 8);
                /* The first two IP-like fields are start,end */
                uint32_t ips[2]; int nip = 0;
                for (int i = 0; i < n && nip < 2; i++) {
                    char *f = trim(fields[i]);
                    uint32_t v;
                    if (ip_parse(f, &v)) ips[nip++] = v;
                }
                if (nip == 2) {
                    t->dhcp_lo = ips[0] < ips[1] ? ips[0] : ips[1];
                    t->dhcp_hi = ips[0] < ips[1] ? ips[1] : ips[0];
                }
            }
        }
        if (!nl) break;
        line = nl + 1;
    }
    free(buf);
}

static void cur_push(sidecar_t *sc, const uint8_t mac[6], uint32_t ip,
                     const char *name) {
    if (!sc) return;
    if (sc->n_cur == sc->cap_cur) {
        size_t ncap = sc->cap_cur ? sc->cap_cur * 2 : 32;
        dyn_entry_t *nb = realloc(sc->cur, ncap * sizeof(*nb));
        if (!nb) return;
        sc->cur     = nb;
        sc->cap_cur = ncap;
    }
    dyn_entry_t *e = &sc->cur[sc->n_cur++];
    memcpy(e->mac, mac, 6);
    e->ip = ip;
    if (name) {
        strncpy(e->name, name, sizeof(e->name) - 1);
        e->name[sizeof(e->name) - 1] = 0;
    } else {
        e->name[0] = 0;
    }
}

static void parse_leases_file(wg_leases_t *t, const char *path) {
    sidecar_t *sc = side_for(t);
    size_t nbytes = 0;
    char *buf = read_small_file(path, 512 * 1024, &nbytes);
    if (!buf) return;
    /* format: "<expiry> <mac> <ip> <hostname> <client-id>" */
    char *line = buf;
    while (*line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        char *s = trim(line);
        if (*s) {
            char *tok[6];
            int n = 0;
            char *p = s;
            while (n < 6) {
                tok[n++] = p;
                char *c = p;
                while (*c && !isspace((unsigned char)*c)) c++;
                if (!*c) break;
                *c = 0;
                p = c + 1;
                while (*p && isspace((unsigned char)*p)) p++;
            }
            if (n >= 4) {
                wg_lease_t l;
                memset(&l, 0, sizeof(l));
                uint8_t mac[6];
                uint32_t ip;
                if (mac_parse(tok[1], mac) && ip_parse(tok[2], &ip)) {
                    l.ip = ip;
                    memcpy(l.mac, mac, 6);
                    if (tok[3] && *tok[3] && strcmp(tok[3], "*") != 0) {
                        strncpy(l.name, tok[3], sizeof(l.name) - 1);
                    }
                    l.is_static = false;
                    l.in_lease_file = true;
                    cur_push(sc, mac, ip, l.name[0] ? l.name : NULL);
                    add(t, &l);
                }
            }
        }
        if (!nl) break;
        line = nl + 1;
    }
    free(buf);
}

/* Was (mac,ip) in the previous snapshot? Returns the prev entry or NULL. */
static const dyn_entry_t *find_prev(const sidecar_t *sc,
                                    const uint8_t mac[6], uint32_t ip) {
    for (size_t i = 0; i < sc->n_prev; i++) {
        if (sc->prev[i].ip == ip &&
            memcmp(sc->prev[i].mac, mac, 6) == 0) return &sc->prev[i];
    }
    return NULL;
}

static const dyn_entry_t *find_cur(const sidecar_t *sc,
                                   const uint8_t mac[6], uint32_t ip) {
    for (size_t i = 0; i < sc->n_cur; i++) {
        if (sc->cur[i].ip == ip &&
            memcmp(sc->cur[i].mac, mac, 6) == 0) return &sc->cur[i];
    }
    return NULL;
}

/* Has any current entry (with this IP but a different MAC) replaced an
 * old one with the same IP? */
static bool replaced_at_ip(const sidecar_t *sc, uint32_t ip,
                           const uint8_t old_mac[6]) {
    for (size_t i = 0; i < sc->n_cur; i++) {
        if (sc->cur[i].ip == ip &&
            memcmp(sc->cur[i].mac, old_mac, 6) != 0) return true;
    }
    return false;
}

static void emit_diff(sidecar_t *sc) {
    if (!sc->cb) return;
    if (!sc->prev_seeded) return;   /* skip the seed-only first reload */
    /* Adds: in cur but not in prev. */
    for (size_t i = 0; i < sc->n_cur; i++) {
        const dyn_entry_t *c = &sc->cur[i];
        if (find_prev(sc, c->mac, c->ip)) continue;
        sc->cb(sc->cb_arg, true, c->mac, c->ip,
               c->name[0] ? c->name : "", NULL);
    }
    /* Removes: in prev but not in cur. The reason is "replaced" if
     * something else now holds the same IP, otherwise "expired". */
    for (size_t i = 0; i < sc->n_prev; i++) {
        const dyn_entry_t *p = &sc->prev[i];
        if (find_cur(sc, p->mac, p->ip)) continue;
        const char *reason = replaced_at_ip(sc, p->ip, p->mac)
                                 ? "replaced" : "expired";
        sc->cb(sc->cb_arg, false, p->mac, p->ip,
               p->name[0] ? p->name : "", reason);
    }
}

static void promote_cur_to_prev(sidecar_t *sc) {
    free(sc->prev);
    sc->prev        = sc->cur;
    sc->n_prev      = sc->n_cur;
    sc->cap_prev    = sc->cap_cur;
    sc->cur         = NULL;
    sc->n_cur       = 0;
    sc->cap_cur     = 0;
    sc->prev_seeded = true;
}

void leases_reload(wg_leases_t *t,
                   const char  *dnsmasq_conf,
                   const char  *dnsmasq_leases,
                   const char  *static_cidr) {
    /* Free items but preserve the sidecar (its prev snapshot is what we
     * diff against this round). leases_free() drops the sidecar too,
     * which is the desired behaviour at shutdown. */
    free(t->items);
    t->items   = NULL;
    t->n       = 0;
    t->cap     = 0;
    t->dhcp_lo = 0;
    t->dhcp_hi = 0;

    sidecar_t *sc = side_for(t);
    /* Reset cur for this round; prev is left intact for diffing. */
    if (sc) {
        free(sc->cur);
        sc->cur     = NULL;
        sc->n_cur   = 0;
        sc->cap_cur = 0;
    }

    if (dnsmasq_conf   && *dnsmasq_conf)   parse_conf(t, dnsmasq_conf);
    if (dnsmasq_leases && *dnsmasq_leases) parse_leases_file(t, dnsmasq_leases);

    /* Recompute is_static by CIDR membership; dhcp-host / leases-file
     * provenance is not itself enough. */
    uint32_t cidr_addr = 0, cidr_mask = 0;
    bool     have_cidr = false;
    if (static_cidr && *static_cidr) {
        if (cidr_parse(static_cidr, &cidr_addr, &cidr_mask)) have_cidr = true;
    }
    size_t n_static = 0;
    for (size_t i = 0; i < t->n; i++) {
        bool s = have_cidr && ip_in_subnet(t->items[i].ip, cidr_addr, cidr_mask);
        t->items[i].is_static = s;
        if (s) n_static++;
    }

    /* Seen-db: bump last_seen for every entry that's currently in the
     * leases file (real DHCP activity), then fill first/last_seen on
     * every entry with a known MAC. */
    if (sc && sc->seen) {
        const uint8_t zero[6] = {0};
        int64_t now = now_wall_s();
        for (size_t i = 0; i < t->n; i++) {
            wg_lease_t *l = &t->items[i];
            if (memcmp(l->mac, zero, 6) == 0) continue;
            if (l->in_lease_file) {
                seen_db_observe(sc->seen, l->mac, now);
            }
            int64_t fs = 0, ls = 0;
            if (seen_db_get(sc->seen, l->mac, &fs, &ls)) {
                l->first_seen = fs;
                l->last_seen  = ls;
            }
        }
    }

    /* Diff against previous snapshot, then promote cur → prev. */
    if (sc) {
        emit_diff(sc);
        promote_cur_to_prev(sc);
    }

    LOG_I("leases: loaded %zu entr%s (%zu static, dhcp-range %s)",
          t->n, t->n == 1 ? "y" : "ies", n_static,
          t->dhcp_lo ? "yes" : "no");
}

const wg_lease_t *leases_by_ip(const wg_leases_t *t, uint32_t ip) {
    for (size_t i = 0; i < t->n; i++) {
        if (t->items[i].ip == ip) return &t->items[i];
    }
    return NULL;
}

const wg_lease_t *leases_by_name(const wg_leases_t *t, const char *name) {
    if (!name || !*name) return NULL;
    for (size_t i = 0; i < t->n; i++) {
        if (strcmp(t->items[i].name, name) == 0) return &t->items[i];
    }
    return NULL;
}

bool leases_dhcp_range(const wg_leases_t *t, uint32_t *lo, uint32_t *hi) {
    if (!t->dhcp_lo) return false;
    if (lo) *lo = t->dhcp_lo;
    if (hi) *hi = t->dhcp_hi;
    return true;
}

void leases_canon_key(const wg_leases_t *t, const char *key,
                      char *out, size_t cap) {
    if (!out || cap == 0) return;
    out[0] = 0;
    if (!key) return;
    uint32_t ip;
    if (ip_parse(key, &ip)) {
        char ipbuf[16];
        ip_format(ip, ipbuf);
        size_t n = strnlen(ipbuf, cap - 1);
        memcpy(out, ipbuf, n);
        out[n] = 0;
        return;
    }
    const wg_lease_t *l = t ? leases_by_name(t, key) : NULL;
    const char *src = (l && l->name[0]) ? l->name : key;
    size_t n = strnlen(src, cap - 1);
    memcpy(out, src, n);
    out[n] = 0;
}

bool leases_resolve_ip(const wg_leases_t *t, const char *key, uint32_t *out) {
    if (!key || !out) return false;
    uint32_t ip;
    if (ip_parse(key, &ip)) { *out = ip; return true; }
    const wg_lease_t *l = t ? leases_by_name(t, key) : NULL;
    if (!l) return false;
    *out = l->ip;
    return true;
}
