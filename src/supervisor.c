#include "supervisor.h"
#include "metrics.h"
#include "log.h"
#include "util.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SUP_THRESHOLD_MIN  5        /* consecutive minutes to trigger */
#define SUP_COOLDOWN_S     (60*60)  /* 1 hour trigger duration */

/* Caps on user-controllable lists. Triggers are naturally bounded by the
 * number of LAN devices but we still refuse pathological sizes. */
#define SUP_TARGETS_MAX    256
#define SUP_TRIGGERS_MAX   512

typedef struct {
    uint32_t ip;           /* 0 = empty slot */
    int      consec;
    bool     matched;      /* matched a target this minute */
} sup_counter_t;

typedef struct {
    char    key[64];       /* canonicalised block key */
    int64_t until;
} sup_trigger_t;

struct wg_supervisor {
    char      **targets;          /* lowercased domain suffixes */
    size_t      n_targets, cap_targets;

    sup_counter_t *counters;
    size_t         n_counters, cap_counters;

    sup_trigger_t *triggers;
    size_t         n_triggers, cap_triggers;

    char       supervised_path[256];
    char       triggers_path  [256];

    bool       dirty_targets;
    bool       dirty_triggers;
};

/* ---------------------------- small utils ------------------------- */

static char *dup_lower(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s);
    char *o = malloc(n + 1);
    if (!o) return NULL;
    for (size_t i = 0; i < n; i++) o[i] = (char)tolower((unsigned char)s[i]);
    o[n] = 0;
    return o;
}

/* Does `domain` (already lowercased) end with `suffix` aligned on a label
 * boundary? e.g. suffix "example.com" matches "example.com" and
 * "x.example.com" but not "abcexample.com". */
static bool label_suffix_match(const char *domain, const char *suffix) {
    size_t dn = strlen(domain), sn = strlen(suffix);
    if (sn == 0 || dn < sn) return false;
    size_t off = dn - sn;
    if (strcmp(domain + off, suffix) != 0) return false;
    if (off == 0) return true;
    return domain[off - 1] == '.';
}

/* --------------------------- new/free ---------------------------- */

wg_supervisor_t *supervisor_new(const char *supervised_path,
                                const char *triggers_path) {
    wg_supervisor_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    if (supervised_path)
        strncpy(s->supervised_path, supervised_path,
                sizeof(s->supervised_path) - 1);
    if (triggers_path)
        strncpy(s->triggers_path, triggers_path,
                sizeof(s->triggers_path) - 1);
    return s;
}

void supervisor_free(wg_supervisor_t *s) {
    if (!s) return;
    for (size_t i = 0; i < s->n_targets; i++) free(s->targets[i]);
    free(s->targets);
    free(s->counters);
    free(s->triggers);
    free(s);
}

/* ---------------------------- load ------------------------------- */

static void grow_targets(wg_supervisor_t *s) {
    if (s->n_targets < s->cap_targets) return;
    if (s->cap_targets >= SUP_TARGETS_MAX) return;
    size_t nc = s->cap_targets ? s->cap_targets * 2 : 16;
    if (nc > SUP_TARGETS_MAX) nc = SUP_TARGETS_MAX;
    char **n = realloc(s->targets, nc * sizeof(*n));
    if (!n) return;
    s->targets = n;
    s->cap_targets = nc;
}

static void grow_triggers(wg_supervisor_t *s) {
    if (s->n_triggers < s->cap_triggers) return;
    if (s->cap_triggers >= SUP_TRIGGERS_MAX) return;
    size_t nc = s->cap_triggers ? s->cap_triggers * 2 : 8;
    if (nc > SUP_TRIGGERS_MAX) nc = SUP_TRIGGERS_MAX;
    sup_trigger_t *n = realloc(s->triggers, nc * sizeof(*n));
    if (!n) return;
    s->triggers = n;
    s->cap_triggers = nc;
}

static int load_targets_file(wg_supervisor_t *s) {
    for (size_t i = 0; i < s->n_targets; i++) free(s->targets[i]);
    s->n_targets = 0;
    if (!s->supervised_path[0]) return 0;
    size_t n = 0;
    char *buf = read_small_file(s->supervised_path, 64 * 1024, &n);
    if (!buf) return 0;
    const char *err = NULL;
    json_val_t *v = json_parse(buf, n, &err);
    free(buf);
    if (!v) {
        LOG_W("supervised: parse %s: %s", s->supervised_path, err ? err : "?");
        return -1;
    }
    if (v->type != JV_ARR) { json_val_free(v); return -1; }
    for (size_t i = 0; i < v->u.arr.n; i++) {
        const json_val_t *e = &v->u.arr.items[i];
        if (e->type != JV_STR) continue;
        char *dup = dup_lower(e->u.str.s);
        if (!dup) continue;
        grow_targets(s);
        if (s->n_targets >= s->cap_targets) { free(dup); continue; }
        s->targets[s->n_targets++] = dup;
    }
    json_val_free(v);
    return 0;
}

static int load_triggers_file(wg_supervisor_t *s) {
    s->n_triggers = 0;
    if (!s->triggers_path[0]) return 0;
    size_t n = 0;
    char *buf = read_small_file(s->triggers_path, 64 * 1024, &n);
    if (!buf) return 0;
    const char *err = NULL;
    json_val_t *v = json_parse(buf, n, &err);
    free(buf);
    if (!v) {
        LOG_W("triggers: parse %s: %s", s->triggers_path, err ? err : "?");
        return -1;
    }
    if (v->type != JV_ARR) { json_val_free(v); return -1; }
    for (size_t i = 0; i < v->u.arr.n; i++) {
        const json_val_t *e = &v->u.arr.items[i];
        if (e->type != JV_OBJ) continue;
        const char *key = NULL;
        int64_t until = 0;
        json_get_str(json_obj_get(e, "key"),   &key);
        json_get_i64(json_obj_get(e, "until"), &until);
        if (!key) continue;
        grow_triggers(s);
        if (s->n_triggers >= s->cap_triggers) continue;
        sup_trigger_t *t = &s->triggers[s->n_triggers++];
        memset(t, 0, sizeof(*t));
        strncpy(t->key, key, sizeof(t->key) - 1);
        t->until = until;
    }
    json_val_free(v);
    return 0;
}

int supervisor_load(wg_supervisor_t *s) {
    if (!s) return -1;
    load_targets_file(s);
    load_triggers_file(s);
    s->dirty_targets  = false;
    s->dirty_triggers = false;
    return 0;
}

/* ---------------------------- save ------------------------------- */

static int save_targets_file(wg_supervisor_t *s) {
    if (!s->supervised_path[0]) return 0;
    json_out_t j;
    json_out_init(&j);
    json_arr_begin(&j);
    for (size_t i = 0; i < s->n_targets; i++) json_str(&j, s->targets[i]);
    json_arr_end(&j);
    int rc = atomic_write(s->supervised_path,
                          j.buf ? j.buf : "[]",
                          j.buf ? j.len : 2);
    json_out_free(&j);
    return rc;
}

static int save_triggers_file(wg_supervisor_t *s) {
    if (!s->triggers_path[0]) return 0;
    json_out_t j;
    json_out_init(&j);
    json_arr_begin(&j);
    for (size_t i = 0; i < s->n_triggers; i++) {
        const sup_trigger_t *t = &s->triggers[i];
        json_obj_begin(&j);
        json_kstr(&j, "key",   t->key);
        json_ki64(&j, "until", t->until);
        json_obj_end(&j);
    }
    json_arr_end(&j);
    int rc = atomic_write(s->triggers_path,
                          j.buf ? j.buf : "[]",
                          j.buf ? j.len : 2);
    json_out_free(&j);
    return rc;
}

int supervisor_save(wg_supervisor_t *s) {
    int rc = 0;
    if (s->dirty_targets)  { rc |= save_targets_file(s);  s->dirty_targets  = false; }
    if (s->dirty_triggers) { rc |= save_triggers_file(s); s->dirty_triggers = false; }
    return rc;
}

/* ---------------------------- matching --------------------------- */

bool supervisor_domain_matches(const wg_supervisor_t *s, const char *domain) {
    if (!s || !domain || !*domain) return false;
    char lo[128];
    size_t dn = strlen(domain);
    if (dn >= sizeof(lo)) dn = sizeof(lo) - 1;
    for (size_t i = 0; i < dn; i++) lo[i] = (char)tolower((unsigned char)domain[i]);
    lo[dn] = 0;
    for (size_t i = 0; i < s->n_targets; i++) {
        if (label_suffix_match(lo, s->targets[i])) return true;
    }
    return false;
}

/* --------------------------- counters ---------------------------- */

static sup_counter_t *find_counter(wg_supervisor_t *s, uint32_t ip, bool create) {
    for (size_t i = 0; i < s->n_counters; i++)
        if (s->counters[i].ip == ip) return &s->counters[i];
    if (!create) return NULL;
    if (s->n_counters >= s->cap_counters) {
        size_t nc = s->cap_counters ? s->cap_counters * 2 : 16;
        sup_counter_t *n = realloc(s->counters, nc * sizeof(*n));
        if (!n) return NULL;
        s->counters    = n;
        s->cap_counters = nc;
    }
    sup_counter_t *c = &s->counters[s->n_counters++];
    memset(c, 0, sizeof(*c));
    c->ip = ip;
    return c;
}

static void reset_counter_for_ip(wg_supervisor_t *s, uint32_t ip) {
    for (size_t i = 0; i < s->n_counters; i++) {
        if (s->counters[i].ip == ip) {
            s->counters[i].consec  = 0;
            s->counters[i].matched = false;
            return;
        }
    }
}

/* --------------------------- observation ------------------------- */

void supervisor_observe(wg_supervisor_t *s, uint32_t client_ip,
                        const char *domain) {
    if (!s || client_ip == 0 || !domain) return;
    if (!supervisor_domain_matches(s, domain)) return;
    sup_counter_t *c = find_counter(s, client_ip, true);
    if (c) c->matched = true;
}

static void ip_to_canon(const wg_leases_t *leases, uint32_t ip,
                        char *out, size_t cap) {
    const wg_lease_t *l = leases_by_ip(leases, ip);
    if (l && l->name[0]) {
        size_t n = strnlen(l->name, cap - 1);
        memcpy(out, l->name, n);
        out[n] = 0;
        return;
    }
    ip_format(ip, out);
}

static void add_trigger(wg_supervisor_t *s, const wg_leases_t *leases,
                        uint32_t client_ip, int64_t now_wall,
                        jsonl_t *jl) {
    char canon[64];
    ip_to_canon(leases, client_ip, canon, sizeof(canon));

    int64_t until = now_wall + SUP_COOLDOWN_S;

    /* update in place if already present */
    for (size_t i = 0; i < s->n_triggers; i++) {
        if (strcmp(s->triggers[i].key, canon) == 0) {
            s->triggers[i].until = until;
            s->dirty_triggers = true;
            goto emit;
        }
    }
    grow_triggers(s);
    if (s->n_triggers >= s->cap_triggers) {
        LOG_W("supervised: triggers at cap (%d); dropping new trigger",
              SUP_TRIGGERS_MAX);
        return;
    }
    sup_trigger_t *t = &s->triggers[s->n_triggers++];
    memset(t, 0, sizeof(*t));
    size_t kn = strnlen(canon, sizeof(t->key) - 1);
    memcpy(t->key, canon, kn);
    t->key[kn] = 0;
    t->until = until;
    s->dirty_triggers = true;

emit:;
    char ipbuf[16];
    ip_format(client_ip, ipbuf);
    metrics_emit_control(jl, now_wall, canon, ipbuf, "block", "supervised");
}

void supervisor_commit_minute(wg_supervisor_t *s,
                              const wg_leases_t *leases,
                              jsonl_t *jl, int64_t now_wall) {
    if (!s) return;
    for (size_t i = 0; i < s->n_counters; i++) {
        sup_counter_t *c = &s->counters[i];
        if (c->matched) {
            c->consec++;
            c->matched = false;
            if (c->consec >= SUP_THRESHOLD_MIN) {
                add_trigger(s, leases, c->ip, now_wall, jl);
                c->consec = 0;
            }
        } else {
            c->consec = 0;
        }
    }
    supervisor_save(s);
}

void supervisor_drop_minute(wg_supervisor_t *s) {
    if (!s) return;
    for (size_t i = 0; i < s->n_counters; i++) {
        s->counters[i].matched = false;
        s->counters[i].consec  = 0;
    }
}

/* ------------------------------ tick ----------------------------- */

void supervisor_tick(wg_supervisor_t *s, const wg_leases_t *leases,
                     int64_t now_wall) {
    if (!s) return;
    size_t w = 0;
    for (size_t r = 0; r < s->n_triggers; r++) {
        const sup_trigger_t *t = &s->triggers[r];
        if (t->until <= now_wall) {
            s->dirty_triggers = true;
            uint32_t ip;
            if (blocks_resolve_ip(leases, t->key, &ip)) {
                reset_counter_for_ip(s, ip);
            }
            continue;
        }
        if (w != r) s->triggers[w] = *t;
        w++;
    }
    s->n_triggers = w;
    supervisor_save(s);
}

/* --------------------------- queries ----------------------------- */

bool supervisor_ip_triggered(const wg_supervisor_t *s,
                             const wg_leases_t *leases,
                             uint32_t ip, int64_t now_wall) {
    if (!s) return false;
    for (size_t i = 0; i < s->n_triggers; i++) {
        if (s->triggers[i].until <= now_wall) continue;
        uint32_t kip;
        if (!blocks_resolve_ip(leases, s->triggers[i].key, &kip)) continue;
        if (kip == ip) return true;
    }
    return false;
}

size_t supervisor_triggered_ips(const wg_supervisor_t *s,
                                const wg_leases_t *leases,
                                int64_t now_wall,
                                uint32_t *out, size_t cap) {
    if (!s || !out || cap == 0) return 0;
    size_t n = 0;
    for (size_t i = 0; i < s->n_triggers && n < cap; i++) {
        if (s->triggers[i].until <= now_wall) continue;
        uint32_t ip;
        if (!blocks_resolve_ip(leases, s->triggers[i].key, &ip)) continue;
        /* de-dupe */
        bool dup = false;
        for (size_t k = 0; k < n; k++) if (out[k] == ip) { dup = true; break; }
        if (dup) continue;
        out[n++] = ip;
    }
    return n;
}

/* ------------------------- target CRUD --------------------------- */

static int find_target_idx(const wg_supervisor_t *s, const char *lo) {
    for (size_t i = 0; i < s->n_targets; i++) {
        if (strcmp(s->targets[i], lo) == 0) return (int)i;
    }
    return -1;
}

int supervisor_add_target(wg_supervisor_t *s, const char *domain) {
    if (!s || !domain || !*domain) return 0;
    char *lo = dup_lower(domain);
    if (!lo) return 0;
    if (find_target_idx(s, lo) >= 0) { free(lo); return 0; }
    if (s->n_targets >= SUP_TARGETS_MAX) {
        LOG_W("supervised: targets at cap (%d); refusing add %s",
              SUP_TARGETS_MAX, lo);
        free(lo);
        return 0;
    }
    grow_targets(s);
    if (s->n_targets >= s->cap_targets) { free(lo); return 0; }
    s->targets[s->n_targets++] = lo;
    s->dirty_targets = true;
    supervisor_save(s);
    return 1;
}

int supervisor_remove_target(wg_supervisor_t *s, const char *domain) {
    if (!s || !domain) return 0;
    char *lo = dup_lower(domain);
    if (!lo) return 0;
    int idx = find_target_idx(s, lo);
    free(lo);
    if (idx < 0) return 0;
    free(s->targets[idx]);
    memmove(&s->targets[idx], &s->targets[idx+1],
            (s->n_targets - (size_t)idx - 1) * sizeof(*s->targets));
    s->n_targets--;
    s->dirty_targets = true;
    supervisor_save(s);
    return 1;
}

/* ------------------------- JSON dump ----------------------------- */

void supervisor_dump_json(const wg_supervisor_t *s, int64_t now_wall,
                          json_out_t *j) {
    json_obj_begin(j);
    json_key(j, "targets");
    json_arr_begin(j);
    if (s) for (size_t i = 0; i < s->n_targets; i++) json_str(j, s->targets[i]);
    json_arr_end(j);

    json_key(j, "triggers");
    json_arr_begin(j);
    if (s) for (size_t i = 0; i < s->n_triggers; i++) {
        const sup_trigger_t *t = &s->triggers[i];
        if (t->until <= now_wall) continue;
        json_obj_begin(j);
        json_kstr(j, "key",   t->key);
        json_ki64(j, "until", t->until);
        json_obj_end(j);
    }
    json_arr_end(j);
    json_obj_end(j);
}
