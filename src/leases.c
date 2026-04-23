#include "leases.h"
#include "log.h"
#include "util.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void leases_init(wg_leases_t *t) {
    memset(t, 0, sizeof(*t));
}

void leases_free(wg_leases_t *t) {
    free(t->items);
    memset(t, 0, sizeof(*t));
}

static void add(wg_leases_t *t, const wg_lease_t *l) {
    /* Upsert by IP so that a later source (leases file) doesn't duplicate a
     * static dhcp-host entry. */
    for (size_t i = 0; i < t->n; i++) {
        if (t->items[i].ip == l->ip) {
            /* Keep is_static if we already have it static; update name/mac. */
            if (!t->items[i].is_static) t->items[i] = *l;
            else if (l->name[0] && !t->items[i].name[0])
                strncpy(t->items[i].name, l->name, sizeof(t->items[i].name) - 1);
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

static void parse_leases_file(wg_leases_t *t, const char *path) {
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
                    add(t, &l);
                }
            }
        }
        if (!nl) break;
        line = nl + 1;
    }
    free(buf);
}

void leases_reload(wg_leases_t *t,
                   const char  *dnsmasq_conf,
                   const char  *dnsmasq_leases) {
    leases_free(t);
    if (dnsmasq_conf   && *dnsmasq_conf)   parse_conf(t, dnsmasq_conf);
    if (dnsmasq_leases && *dnsmasq_leases) parse_leases_file(t, dnsmasq_leases);
    LOG_I("leases: loaded %zu entr%s (dhcp-range %s)",
          t->n, t->n == 1 ? "y" : "ies",
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
