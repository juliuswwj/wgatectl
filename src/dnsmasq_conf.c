#include "dnsmasq_conf.h"
#include "log.h"
#include "util.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool dnsmasq_name_is_valid(const char *s) {
    if (!s) return false;
    size_t n = strlen(s);
    if (n == 0 || n > 63) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        bool ok = (i == 0)
            ? (isalnum(c) != 0)
            : (isalnum(c) || c == '-' || c == '.' || c == '_');
        if (!ok) return false;
    }
    return true;
}

/* -------- small append-buffer -------- */

typedef struct { char *p; size_t n; size_t cap; } buf_t;

static int buf_append(buf_t *b, const char *s, size_t n) {
    if (b->n + n + 1 > b->cap) {
        size_t nc = b->cap ? b->cap : 4096;
        while (nc < b->n + n + 1) nc *= 2;
        char *np = realloc(b->p, nc);
        if (!np) return -1;
        b->p = np; b->cap = nc;
    }
    memcpy(b->p + b->n, s, n);
    b->n += n;
    b->p[b->n] = 0;
    return 0;
}

/* -------- line parsing -------- */

static char *lstrip(char *s) {
    while (*s == ' ' || *s == '\t') s++;
    return s;
}
static void rstrip(char *s) {
    char *e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r')) *--e = 0;
}

/* Split rhs on ',' into up to `max` fields (in-place). Returns count. */
static int split_commas(char *s, char **out, int max) {
    int n = 0;
    char *p = s;
    while (n < max) {
        out[n++] = p;
        char *c = strchr(p, ',');
        if (!c) break;
        *c = 0;
        p = c + 1;
    }
    return n;
}

/* dnsmasq's dhcp-host accepts these extension prefixes on the MAC side.
 * We recognise them so they aren't mistaken for a hostname. */
static bool field_is_metatag(const char *f) {
    if (!f || !*f) return false;
    return strncmp(f, "id:",  3) == 0 ||
           strncmp(f, "set:", 4) == 0 ||
           strncmp(f, "tag:", 4) == 0 ||
           strncmp(f, "net:", 4) == 0 ||     /* deprecated alias for tag: */
           strcmp (f, "ignore") == 0;
}

/* Lease time, per dnsmasq(8): [0-9]+[hmsw]? or "infinite". Recognise so
 * it isn't confused with a hostname. */
static bool field_is_duration(const char *f) {
    if (!f || !*f) return false;
    if (strcmp(f, "infinite") == 0) return true;
    size_t n = strlen(f);
    size_t end = n;
    char last = f[n - 1];
    if (last == 'h' || last == 'm' || last == 's' || last == 'w') {
        if (n == 1) return false;
        end = n - 1;
    }
    for (size_t i = 0; i < end; i++)
        if (!isdigit((unsigned char)f[i])) return false;
    return true;
}

/* Classify fields into (first-MAC, IP, name). A line may contain
 * multiple MAC fields (MAC-aliasing form); we treat them all as MAC.
 * `name_idx` receives the first field that is neither MAC, IP,
 * metatag, nor duration — i.e. the actual hostname, or -1 if absent.
 *
 * The returned indexes point into `fields[]`. `fields[i]` has already
 * been l/r-stripped in place. */
static void classify_fields(char **fields, int n,
                            int *first_mac_idx, int *ip_idx,
                            int *name_idx,
                            uint8_t macs_out[][6], int *n_macs_out) {
    *first_mac_idx = *ip_idx = *name_idx = -1;
    if (n_macs_out) *n_macs_out = 0;
    for (int i = 0; i < n; i++) {
        char *f = lstrip(fields[i]);
        rstrip(f);
        fields[i] = f;
        if (!*f) continue;
        uint8_t m[6]; uint32_t v;
        if (mac_parse(f, m)) {
            if (*first_mac_idx < 0) *first_mac_idx = i;
            if (n_macs_out && *n_macs_out < 4) {
                memcpy(macs_out[*n_macs_out], m, 6);
                (*n_macs_out)++;
            }
            continue;
        }
        if (*ip_idx < 0 && ip_parse(f, &v)) { *ip_idx = i; continue; }
        if (field_is_metatag(f))  continue;
        if (field_is_duration(f)) continue;
        if (*name_idx < 0)        *name_idx = i;
    }
}

static bool mac_is_zero(const uint8_t mac[6]) {
    for (int i = 0; i < 6; i++) if (mac[i]) return false;
    return true;
}

static bool line_mac_matches(const uint8_t macs[][6], int n_macs,
                             const uint8_t target[6]) {
    for (int i = 0; i < n_macs; i++)
        if (memcmp(macs[i], target, 6) == 0) return true;
    return false;
}

/* -------- main entry point -------- */

dnsmasq_name_rc_t dnsmasq_set_host_name(const char *conf_path,
                                        const uint8_t mac[6],
                                        uint32_t ip,
                                        const char *name,
                                        bool *changed_out) {
    if (changed_out) *changed_out = false;
    if (!conf_path || !*conf_path || !mac || !name) return DNS_NAME_IO;
    if (mac_is_zero(mac)) return DNS_NAME_NO_MAC;
    if (!dnsmasq_name_is_valid(name)) return DNS_NAME_INVALID;
    (void)ip;   /* reserved for future use; we never overwrite an existing IP */

    size_t nbytes = 0;
    char *src = read_small_file(conf_path, 1024 * 1024, &nbytes);
    if (!src) return DNS_NAME_IO;

    /* First pass: uniqueness scan over a throwaway copy. Any dhcp-host
     * line whose hostname equals `name` and whose MAC differs from the
     * target blocks the operation; the file is left untouched. */
    {
        char *scan = malloc(nbytes + 1);
        if (!scan) { free(src); return DNS_NAME_IO; }
        memcpy(scan, src, nbytes + 1);
        char *line = scan;
        while (*line) {
            char *nl = strchr(line, '\n');
            if (nl) *nl = 0;
            char *s = lstrip(line);
            rstrip(s);
            if (*s && *s != '#' && strncmp(s, "dhcp-host=", 10) == 0) {
                char *fields[8];
                int nf = split_commas(s + 10, fields, 8);
                int mi, ii, ni, n_macs = 0;
                uint8_t macs[4][6];
                classify_fields(fields, nf, &mi, &ii, &ni, macs, &n_macs);
                if (ni >= 0 && strcmp(fields[ni], name) == 0) {
                    if (!line_mac_matches(macs, n_macs, mac)) {
                        free(scan); free(src);
                        return DNS_NAME_DUPLICATE;
                    }
                }
            }
            if (!nl) break;
            line = nl + 1;
        }
        free(scan);
    }

    /* Second pass: emit the file byte-for-byte, replacing only the name
     * token on the single dhcp-host line whose MAC matches `mac`. */
    buf_t out = { 0 };
    bool updated = false;

    char *line = src;
    while (*line) {
        char *nl = strchr(line, '\n');
        size_t raw_len = nl ? (size_t)(nl - line) : strlen(line);

        /* Default: copy the original line verbatim. Only if we decide
         * to rewrite do we switch to emitting from `work`. */
        bool did_rewrite = false;

        /* Parse a mutable copy to see if this is our target. */
        char *work = malloc(raw_len + 1);
        if (!work) { free(out.p); free(src); return DNS_NAME_IO; }
        memcpy(work, line, raw_len);
        work[raw_len] = 0;

        char *s = lstrip(work);
        rstrip(s);

        if (!updated && *s && *s != '#' &&
            strncmp(s, "dhcp-host=", 10) == 0) {

            /* Find the "dhcp-host=" anchor inside the original `line`
             * so we can preserve any leading whitespace verbatim. */
            size_t indent = 0;
            while (indent < raw_len &&
                   (line[indent] == ' ' || line[indent] == '\t'))
                indent++;
            /* strncmp against the stripped copy already confirmed
             * dhcp-host= starts at `line + indent`. */

            char *rhs = s + 10;
            char *fields[8];
            int nf = split_commas(rhs, fields, 8);
            int mi, ii, ni, n_macs = 0;
            uint8_t macs[4][6];
            classify_fields(fields, nf, &mi, &ii, &ni, macs, &n_macs);

            if (line_mac_matches(macs, n_macs, mac)) {
                /* Build only the new RHS. Every token is preserved
                 * verbatim (including original MAC casing and lease
                 * time position); only the name field is replaced, or
                 * inserted if absent. */
                buf_t rhs_out = { 0 };
                if (ni >= 0) {
                    /* replace the name field in place */
                    bool first = true;
                    for (int i = 0; i < nf; i++) {
                        if (!fields[i]) continue;
                        const char *emit = (i == ni) ? name : fields[i];
                        if (!*emit) continue;
                        if (!first) buf_append(&rhs_out, ",", 1);
                        first = false;
                        buf_append(&rhs_out, emit, strlen(emit));
                    }
                } else {
                    /* no name existed — insert just after the last of
                     * MAC / IP (whichever appeared later in the line),
                     * keeping every other token where it was */
                    int insert_after = mi;
                    if (ii > insert_after) insert_after = ii;
                    bool first = true;
                    for (int i = 0; i < nf; i++) {
                        if (!fields[i] || !*fields[i]) continue;
                        if (!first) buf_append(&rhs_out, ",", 1);
                        first = false;
                        buf_append(&rhs_out, fields[i], strlen(fields[i]));
                        if (i == insert_after) {
                            buf_append(&rhs_out, ",", 1);
                            buf_append(&rhs_out, name, strlen(name));
                        }
                    }
                }

                /* leading indent + "dhcp-host=" + new rhs */
                buf_append(&out, line, indent);
                buf_append(&out, "dhcp-host=", 10);
                buf_append(&out, rhs_out.p ? rhs_out.p : "",
                                 rhs_out.p ? rhs_out.n : 0);
                free(rhs_out.p);
                if (nl) buf_append(&out, "\n", 1);
                did_rewrite = true;
                updated = true;
            }
        }

        if (!did_rewrite) {
            buf_append(&out, line, raw_len);
            if (nl) buf_append(&out, "\n", 1);
        }
        free(work);
        if (!nl) break;
        line = nl + 1;
    }

    if (!updated) {
        /* No existing line for this MAC — append a new one in the
         * NAME,IP,MAC order this repo's conf follows, so any sibling
         * scripts that key off field position keep working. */
        if (out.n && out.p[out.n - 1] != '\n') buf_append(&out, "\n", 1);
        char macbuf[18];
        char ipbuf[16] = "";
        mac_format(mac, macbuf);
        if (ip) ip_format(ip, ipbuf);
        char newline[128];
        int nn;
        if (ip)
            nn = snprintf(newline, sizeof(newline),
                          "dhcp-host=%s,%s,%s\n", name, ipbuf, macbuf);
        else
            nn = snprintf(newline, sizeof(newline),
                          "dhcp-host=%s,%s\n", name, macbuf);
        if (nn <= 0 || (size_t)nn >= sizeof(newline)) {
            free(out.p); free(src); return DNS_NAME_IO;
        }
        buf_append(&out, newline, (size_t)nn);
    }

    /* Idempotent no-op: nothing to write. */
    bool file_same = (out.n == nbytes) && memcmp(out.p, src, nbytes) == 0;
    free(src);
    if (file_same) {
        free(out.p);
        return DNS_NAME_OK;  /* *changed_out stays false */
    }

    if (atomic_write(conf_path, out.p, out.n) < 0) {
        free(out.p);
        LOG_E("dnsmasq_conf: atomic_write(%s) failed", conf_path);
        return DNS_NAME_IO;
    }
    free(out.p);
    if (changed_out) *changed_out = true;
    char macbuf[18]; mac_format(mac, macbuf);
    LOG_I("dnsmasq_conf: set name=%s for %s in %s", name, macbuf, conf_path);
    return DNS_NAME_OK;
}
