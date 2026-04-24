#include "sniffer.h"
#include "log.h"
#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>

/* ------------------- reverse map (client,server) → qname ------------------
 * Open-addressed hash with linear probing. Entries age out after TTL.
 * Capacity is a power of two; we size it generously for a home LAN. */

#define REV_CAP     8192
#define REV_TTL_S   (10 * 60)

typedef struct {
    uint32_t client_ip;
    uint32_t server_ip;
    uint32_t last_seen_s;   /* 0 = empty slot */
    char     name[96];
} rev_entry_t;

struct wg_sniffer {
    pcap_t           *pcap;
    int               fd;
    char              errbuf[PCAP_ERRBUF_SIZE];

    uint32_t          net_addr;
    uint32_t          net_mask;

    ipset_mgr_t      *ipset;
    wg_metrics_t     *metrics;

    rev_entry_t       rev[REV_CAP];
};

static uint32_t rev_hash(uint32_t c, uint32_t s) {
    uint64_t x = ((uint64_t)c << 32) | s;
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdull;
    x ^= x >> 33;
    return (uint32_t)(x & (REV_CAP - 1));
}

static void rev_insert(struct wg_sniffer *s, uint32_t c, uint32_t sip,
                       const char *name, uint32_t now_s) {
    uint32_t idx = rev_hash(c, sip);
    for (int i = 0; i < 16; i++) {
        rev_entry_t *e = &s->rev[(idx + i) & (REV_CAP - 1)];
        if (e->last_seen_s == 0 || (now_s - e->last_seen_s) > REV_TTL_S ||
            (e->client_ip == c && e->server_ip == sip)) {
            e->client_ip   = c;
            e->server_ip   = sip;
            e->last_seen_s = now_s ? now_s : 1;
            strncpy(e->name, name, sizeof(e->name) - 1);
            e->name[sizeof(e->name) - 1] = 0;
            return;
        }
    }
    /* fallback: overwrite slot idx */
    rev_entry_t *e = &s->rev[idx];
    e->client_ip   = c;
    e->server_ip   = sip;
    e->last_seen_s = now_s ? now_s : 1;
    strncpy(e->name, name, sizeof(e->name) - 1);
    e->name[sizeof(e->name) - 1] = 0;
}

static const char *rev_lookup(struct wg_sniffer *s, uint32_t c, uint32_t sip,
                              uint32_t now_s) {
    uint32_t idx = rev_hash(c, sip);
    for (int i = 0; i < 16; i++) {
        rev_entry_t *e = &s->rev[(idx + i) & (REV_CAP - 1)];
        if (e->last_seen_s == 0) return NULL;
        if (e->client_ip == c && e->server_ip == sip) {
            if ((now_s - e->last_seen_s) > REV_TTL_S) return NULL;
            return e->name;
        }
    }
    return NULL;
}

/* ------------------------- DNS name decoding ----------------------------- */

/* Decode a DNS name starting at `p` (points somewhere inside the DNS
 * payload `base..base+len`). Writes a dotted NUL-terminated string into
 * out[outcap]. Returns the offset past the end of the name (NOT following
 * pointer targets) or -1 on error. */
static int dns_read_name(const uint8_t *base, size_t len, size_t off,
                         char *out, size_t outcap) {
    size_t olen = 0;
    size_t p = off;
    int jumps = 0;
    size_t first_return = 0;
    bool jumped = false;

    while (p < len) {
        uint8_t b = base[p];
        if (b == 0) {
            p += 1;
            if (!jumped) first_return = p;
            if (olen == 0 && outcap > 0) out[0] = 0;
            else if (olen < outcap) out[olen] = 0;
            else if (outcap > 0)    out[outcap - 1] = 0;
            return (int)(jumped ? first_return : p);
        }
        if ((b & 0xC0) == 0xC0) {
            if (p + 1 >= len) return -1;
            uint16_t ptr = (uint16_t)(((b & 0x3F) << 8) | base[p + 1]);
            if (!jumped) first_return = p + 2;
            jumped = true;
            if (++jumps > 16 || ptr >= len) return -1;
            p = ptr;
            continue;
        }
        if ((b & 0xC0) != 0) return -1;  /* EDNS extended labels not supported */
        size_t lblen = b;
        p += 1;
        if (p + lblen > len) return -1;
        if (olen + lblen + 1 >= outcap) return -1;  /* too long */
        if (olen) out[olen++] = '.';
        memcpy(out + olen, base + p, lblen);
        /* lowercase on the fly */
        for (size_t k = 0; k < lblen; k++) {
            char c = out[olen + k];
            if (c >= 'A' && c <= 'Z') out[olen + k] = (char)(c + 32);
        }
        olen += lblen;
        p += lblen;
    }
    return -1;
}

/* ------------------------- DNS message parsing --------------------------- */

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qd, an, ns, ar;
} dns_hdr_t;

static bool dns_parse_header(const uint8_t *p, size_t n, dns_hdr_t *h) {
    if (n < 12) return false;
    h->id    = (uint16_t)(p[0] << 8) | p[1];
    h->flags = (uint16_t)(p[2] << 8) | p[3];
    h->qd    = (uint16_t)(p[4] << 8) | p[5];
    h->an    = (uint16_t)(p[6] << 8) | p[7];
    h->ns    = (uint16_t)(p[8] << 8) | p[9];
    h->ar    = (uint16_t)(p[10] << 8) | p[11];
    return true;
}

/* Returns offset after the Question section (or -1). */
static int dns_skip_question(const uint8_t *p, size_t n, int off,
                             char *qname, size_t cap) {
    int next = dns_read_name(p, n, (size_t)off, qname, cap);
    if (next < 0) return -1;
    if ((size_t)next + 4 > n) return -1;
    return next + 4;  /* skip QTYPE + QCLASS */
}

/* Walk the answer section; for each A record, call visitor. */
typedef void (*answer_visitor)(void *ctx, uint32_t ip, uint32_t ttl);

static int dns_walk_answers(const uint8_t *p, size_t n, int off, int ancount,
                            answer_visitor fn, void *ctx) {
    char tmp[256];
    for (int i = 0; i < ancount; i++) {
        int next = dns_read_name(p, n, (size_t)off, tmp, sizeof(tmp));
        if (next < 0) return -1;
        off = next;
        if ((size_t)off + 10 > n) return -1;
        uint16_t type = (uint16_t)(p[off] << 8) | p[off + 1];
        /* uint16_t cls  = (uint16_t)(p[off+2] << 8) | p[off+3]; */
        uint32_t ttl = (uint32_t)(p[off + 4] << 24) | ((uint32_t)p[off + 5] << 16)
                     | ((uint32_t)p[off + 6] << 8)  |  p[off + 7];
        uint16_t rdl = (uint16_t)(p[off + 8] << 8) | p[off + 9];
        off += 10;
        if ((size_t)off + rdl > n) return -1;
        if (type == 1 /* A */ && rdl == 4) {
            uint32_t ip = ((uint32_t)p[off] << 24) | ((uint32_t)p[off + 1] << 16)
                        | ((uint32_t)p[off + 2] << 8) | p[off + 3];
            if (fn) fn(ctx, ip, ttl);
        }
        off += rdl;
    }
    return off;
}

/* ---------------- sniffer callback ---------------- */

typedef struct {
    struct wg_sniffer *s;
    uint32_t           client_ip;
    const char        *qname;
    uint32_t           now_s;
    bool               is_whitelist;
} ans_ctx_t;

static void answer_visit(void *vctx, uint32_t ip, uint32_t ttl) {
    (void)ttl;
    ans_ctx_t *c = vctx;
    rev_insert(c->s, c->client_ip, ip, c->qname, c->now_s);
    if (c->is_whitelist) ipset_mgr_add(c->s->ipset, ip);
}

static bool in_lan(struct wg_sniffer *s, uint32_t ip) {
    return ip_in_subnet(ip, s->net_addr, s->net_mask);
}

static void handle_dns(struct wg_sniffer *s, uint32_t src_ip, uint32_t dst_ip,
                       const uint8_t *payload, size_t plen, uint32_t now_s) {
    dns_hdr_t h;
    if (!dns_parse_header(payload, plen, &h)) return;
    bool is_response = (h.flags & 0x8000) != 0;
    if (h.qd == 0) return;

    char qname[256];
    qname[0] = 0;
    int off = dns_skip_question(payload, plen, 12, qname, sizeof(qname));
    if (off < 0) return;

    if (!is_response) {
        /* query: record the activity for the src LAN client */
        if (in_lan(s, src_ip))
            metrics_observe_dns_query(s->metrics, src_ip, qname);
        return;
    }

    /* response: populate reverse map keyed on the client that asked
     * (destination of the response). */
    if (!in_lan(s, dst_ip)) return;
    ans_ctx_t ac = {
        .s = s, .client_ip = dst_ip, .qname = qname, .now_s = now_s,
        .is_whitelist = ipset_mgr_is_whitelist_fqdn(qname)
    };
    dns_walk_answers(payload, plen, off, h.an, answer_visit, &ac);
}

static void pcap_cb(u_char *user, const struct pcap_pkthdr *hdr,
                    const u_char *pkt) {
    struct wg_sniffer *s = (struct wg_sniffer *)user;
    const uint8_t *p = pkt;
    size_t caplen = hdr->caplen;
    if (caplen < sizeof(struct ether_header)) return;

    const struct ether_header *eh = (const struct ether_header *)p;
    uint16_t etype = ntohs(eh->ether_type);
    size_t off = sizeof(*eh);

    /* handle one level of 802.1Q */
    if (etype == ETHERTYPE_VLAN) {
        if (caplen < off + 4) return;
        etype = (uint16_t)(p[off + 2] << 8) | p[off + 3];
        off += 4;
    }
    if (etype != ETHERTYPE_IP) return;
    if (caplen < off + 20) return;

    const uint8_t *ip = p + off;
    uint8_t ihl = (ip[0] & 0x0F) * 4;
    if (ihl < 20 || caplen < off + ihl) return;
    uint8_t proto = ip[9];
    uint32_t src = ((uint32_t)ip[12] << 24) | ((uint32_t)ip[13] << 16)
                 | ((uint32_t)ip[14] << 8)  |  ip[15];
    uint32_t dst = ((uint32_t)ip[16] << 24) | ((uint32_t)ip[17] << 16)
                 | ((uint32_t)ip[18] << 8)  |  ip[19];
    uint16_t ip_total_len = (uint16_t)(ip[2] << 8) | ip[3];
    size_t l4off = off + ihl;
    size_t l4cap = (caplen > l4off) ? (caplen - l4off) : 0;

    uint32_t now_s = (uint32_t)hdr->ts.tv_sec;

    /* DNS is on UDP port 53 — handle separately (populates reverse map,
     * triggers ipset add for whitelisted FQDNs) and don't count those
     * bytes as normal traffic. Everything else (TCP of any flavor plus
     * non-DNS UDP, including QUIC/HTTP3 on port 443) falls through to
     * the byte-counting path. */
    if (proto == 17 /* UDP */) {
        if (l4cap < 8) return;
        uint16_t sport = (uint16_t)(p[l4off] << 8) | p[l4off + 1];
        uint16_t dport = (uint16_t)(p[l4off + 2] << 8) | p[l4off + 3];
        if (sport == 53 || dport == 53) {
            const uint8_t *dns = p + l4off + 8;
            size_t dnslen = l4cap - 8;
            handle_dns(s, src, dst, dns, dnslen, now_s);
            return;
        }
        /* fall through: non-DNS UDP */
    } else if (proto != 6 /* TCP */) {
        return;
    }

    /* Count bytes for whichever endpoint is inside the LAN.
     * rtset.py only counted download direction (dst in LAN); we do the
     * same so the existing usage-credit heuristic stays calibrated. */
    if (!in_lan(s, dst)) return;
    const char *domain = rev_lookup(s, dst, src, now_s);
    /* Wire length = IP total length + L2 header (close enough; we don't
     * count the 4-byte FCS that was stripped by the driver). */
    uint32_t wire_len = (uint32_t)ip_total_len + (uint32_t)(off);
    metrics_observe_flow(s->metrics, dst, src, domain, wire_len);
}

/* ---------------- public API ---------------- */

wg_sniffer_t *sniffer_open(const wg_sniffer_cfg_t *cfg) {
    wg_sniffer_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->net_addr = cfg->net_addr;
    s->net_mask = cfg->net_mask;
    s->ipset    = cfg->ipset;
    s->metrics  = cfg->metrics;

    s->pcap = pcap_create(cfg->iface, s->errbuf);
    if (!s->pcap) {
        LOG_E("pcap_create(%s): %s", cfg->iface, s->errbuf);
        free(s);
        return NULL;
    }
    pcap_set_snaplen(s->pcap, 512);         /* DNS answer fits easily */
    pcap_set_timeout(s->pcap, 100);
    pcap_set_immediate_mode(s->pcap, 1);
    pcap_set_buffer_size(s->pcap, 2 * 1024 * 1024);
    pcap_set_promisc(s->pcap, 0);

    int rc = pcap_activate(s->pcap);
    if (rc < 0) {
        LOG_E("pcap_activate(%s): %s", cfg->iface, pcap_geterr(s->pcap));
        pcap_close(s->pcap);
        free(s);
        return NULL;
    }
    if (pcap_datalink(s->pcap) != DLT_EN10MB)
        LOG_W("sniffer: iface %s is not Ethernet (datalink=%d)",
              cfg->iface, pcap_datalink(s->pcap));

    struct bpf_program prog;
    if (pcap_compile(s->pcap, &prog, "tcp or udp", 1,
                     PCAP_NETMASK_UNKNOWN) < 0) {
        LOG_E("pcap_compile: %s", pcap_geterr(s->pcap));
        pcap_close(s->pcap);
        free(s);
        return NULL;
    }
    if (pcap_setfilter(s->pcap, &prog) < 0) {
        LOG_E("pcap_setfilter: %s", pcap_geterr(s->pcap));
        pcap_freecode(&prog);
        pcap_close(s->pcap);
        free(s);
        return NULL;
    }
    pcap_freecode(&prog);

    if (pcap_setnonblock(s->pcap, 1, s->errbuf) < 0)
        LOG_W("pcap_setnonblock: %s", s->errbuf);

    s->fd = pcap_get_selectable_fd(s->pcap);
    if (s->fd < 0) {
        LOG_E("pcap has no selectable fd");
        pcap_close(s->pcap);
        free(s);
        return NULL;
    }
    LOG_I("sniffer: capturing on %s (fd=%d)", cfg->iface, s->fd);
    return s;
}

int sniffer_fd(const wg_sniffer_t *s) { return s ? s->fd : -1; }

int sniffer_poll(wg_sniffer_t *s) {
    if (!s || !s->pcap) return -1;
    int n = pcap_dispatch(s->pcap, 128, pcap_cb, (u_char *)s);
    if (n < 0) {
        LOG_W("pcap_dispatch: %s", pcap_geterr(s->pcap));
        return -1;
    }
    return n;
}

void sniffer_close(wg_sniffer_t *s) {
    if (!s) return;
    if (s->pcap) pcap_close(s->pcap);
    free(s);
}
