#include "schedule.h"
#include "supervisor.h"
#include "log.h"
#include "util.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Hard caps: prevent API floods from growing these lists without bound
 * (and bloating the persisted JSON). Normal operation keeps these well
 * under the cap; a WARN log fires when we hit the ceiling. */
#define OVERRIDES_MAX 256
#define GRANTS_MAX    512

/* ------------------------------ model ------------------------------ */

typedef struct {
    uint8_t    wdays_mask;   /* bit 0 = Sun, bit 6 = Sat */
    uint16_t   hhmm;         /* 0..2359 */
    sch_mode_t mode;
} sch_base_t;

typedef struct {
    char       id[24];
    int64_t    at;
    int64_t    expires_at;    /* 0 = no expiry */
    sch_mode_t mode;
    char       reason[64];
} sch_override_t;

typedef struct {
    char    key[64];
    int64_t until;
    char    reason[64];
} sch_grant_t;

struct wg_schedule {
    sch_base_t         base[16];
    size_t             n_base;

    sch_override_t    *overrides;
    size_t             n_overrides, cap_overrides;

    sch_grant_t       *grants;
    size_t             n_grants, cap_grants;

    uint64_t           id_counter;

    char               schedule_path[256];
    char               grants_path[256];

    bool               dirty_schedule;
    bool               dirty_grants;
};

const char *sch_mode_name(sch_mode_t m) {
    switch (m) {
        case SCH_MODE_CLOSED:     return "closed";
        case SCH_MODE_SUPERVISED: return "supervised";
        case SCH_MODE_OPEN:       return "open";
    }
    return "?";
}

bool sch_mode_parse(const char *s, sch_mode_t *out) {
    if (!s || !out) return false;
    if      (!strcmp(s, "closed"))     { *out = SCH_MODE_CLOSED;     return true; }
    else if (!strcmp(s, "supervised")) { *out = SCH_MODE_SUPERVISED; return true; }
    else if (!strcmp(s, "open"))       { *out = SCH_MODE_OPEN;       return true; }
    return false;
}

/* ------------------------------ defaults --------------------------- */

/* Default weekly base (local time):
 *   daily 07:00 → supervised
 *   daily 18:00 → open
 *   Mon/Wed/Thu/Sun 22:30 → closed   (bits 0,1,3,4 = 0x1B)
 *   Tue/Fri/Sat     23:30 → closed   (bits 2,5,6   = 0x64)
 */
static const sch_base_t kDefaultBase[] = {
    { 0x7F, 700,  SCH_MODE_SUPERVISED },
    { 0x7F, 1800, SCH_MODE_OPEN       },
    { 0x1B, 2230, SCH_MODE_CLOSED     },
    { 0x64, 2330, SCH_MODE_CLOSED     },
};

static void apply_defaults(wg_schedule_t *s) {
    s->n_base = sizeof(kDefaultBase) / sizeof(*kDefaultBase);
    memcpy(s->base, kDefaultBase, sizeof(kDefaultBase));
}

/* ------------------------------ new/free --------------------------- */

wg_schedule_t *schedule_new(const char *schedule_path, const char *grants_path) {
    wg_schedule_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    if (schedule_path) {
        strncpy(s->schedule_path, schedule_path, sizeof(s->schedule_path) - 1);
    }
    if (grants_path) {
        strncpy(s->grants_path, grants_path, sizeof(s->grants_path) - 1);
    }
    apply_defaults(s);
    return s;
}

void schedule_free(wg_schedule_t *s) {
    if (!s) return;
    free(s->overrides);
    free(s->grants);
    free(s);
}

/* ---------------------------- JSON helpers ------------------------- */

static bool parse_wdays_mask(const char *s, uint8_t *out) {
    if (!s) return false;
    if (strlen(s) != 7) return false;
    uint8_t m = 0;
    for (int i = 0; i < 7; i++) {
        if      (s[i] == '1') m |= (uint8_t)(1u << i);
        else if (s[i] == '0') { /* no-op */ }
        else return false;
    }
    *out = m;
    return true;
}

static void format_wdays_mask(uint8_t m, char *out /* 8 */) {
    for (int i = 0; i < 7; i++) out[i] = (m & (1u << i)) ? '1' : '0';
    out[7] = 0;
}

static bool parse_hhmm_str(const char *s, uint16_t *out) {
    if (!s) return false;
    size_t n = strlen(s);
    if (n != 4) return false;
    for (size_t i = 0; i < 4; i++) if (!isdigit((unsigned char)s[i])) return false;
    int hh = (s[0]-'0')*10 + (s[1]-'0');
    int mm = (s[2]-'0')*10 + (s[3]-'0');
    if (hh < 0 || hh > 23 || mm < 0 || mm > 59) return false;
    *out = (uint16_t)(hh*100 + mm);
    return true;
}

static void format_hhmm(uint16_t hhmm, char *out /* 5 */) {
    int hh = hhmm / 100, mm = hhmm % 100;
    out[0] = (char)('0' + (hh/10));
    out[1] = (char)('0' + (hh%10));
    out[2] = (char)('0' + (mm/10));
    out[3] = (char)('0' + (mm%10));
    out[4] = 0;
}

/* ---------------------------- load --------------------------------- */

static void grow_overrides(wg_schedule_t *s) {
    if (s->n_overrides < s->cap_overrides) return;
    if (s->cap_overrides >= OVERRIDES_MAX) return;
    size_t nc = s->cap_overrides ? s->cap_overrides * 2 : 8;
    if (nc > OVERRIDES_MAX) nc = OVERRIDES_MAX;
    sch_override_t *n = realloc(s->overrides, nc * sizeof(*n));
    if (!n) return;
    s->overrides = n;
    s->cap_overrides = nc;
}

static void grow_grants(wg_schedule_t *s) {
    if (s->n_grants < s->cap_grants) return;
    if (s->cap_grants >= GRANTS_MAX) return;
    size_t nc = s->cap_grants ? s->cap_grants * 2 : 8;
    if (nc > GRANTS_MAX) nc = GRANTS_MAX;
    sch_grant_t *n = realloc(s->grants, nc * sizeof(*n));
    if (!n) return;
    s->grants = n;
    s->cap_grants = nc;
}

static int load_schedule_file(wg_schedule_t *s) {
    if (!s->schedule_path[0]) return 0;
    size_t n = 0;
    char *buf = read_small_file(s->schedule_path, 128 * 1024, &n);
    if (!buf) return 0;
    const char *err = NULL;
    json_val_t *v = json_parse(buf, n, &err);
    free(buf);
    if (!v) {
        LOG_W("schedule: parse %s: %s", s->schedule_path, err ? err : "?");
        return -1;
    }
    if (v->type != JV_OBJ) { json_val_free(v); return -1; }

    const json_val_t *base = json_obj_get(v, "base");
    if (base && base->type == JV_ARR) {
        s->n_base = 0;
        for (size_t i = 0; i < base->u.arr.n && s->n_base < sizeof(s->base)/sizeof(*s->base); i++) {
            const json_val_t *e = &base->u.arr.items[i];
            if (e->type != JV_OBJ) continue;
            const char *wds = NULL, *hm = NULL, *md = NULL;
            json_get_str(json_obj_get(e, "wdays"), &wds);
            json_get_str(json_obj_get(e, "hhmm"),  &hm);
            json_get_str(json_obj_get(e, "mode"),  &md);
            uint8_t mask = 0;
            uint16_t hhmm = 0;
            sch_mode_t m = SCH_MODE_OPEN;
            if (!parse_wdays_mask(wds, &mask)) continue;
            if (!parse_hhmm_str(hm, &hhmm))    continue;
            if (!sch_mode_parse(md, &m))       continue;
            s->base[s->n_base].wdays_mask = mask;
            s->base[s->n_base].hhmm       = hhmm;
            s->base[s->n_base].mode       = m;
            s->n_base++;
        }
        if (s->n_base == 0) apply_defaults(s);
    }

    const json_val_t *ov = json_obj_get(v, "overrides");
    if (ov && ov->type == JV_ARR) {
        for (size_t i = 0; i < ov->u.arr.n; i++) {
            const json_val_t *e = &ov->u.arr.items[i];
            if (e->type != JV_OBJ) continue;
            const char *id = NULL, *md = NULL, *reason = NULL;
            int64_t at = 0, exp = 0;
            json_get_str(json_obj_get(e, "id"),         &id);
            json_get_str(json_obj_get(e, "mode"),       &md);
            json_get_str(json_obj_get(e, "reason"),     &reason);
            json_get_i64(json_obj_get(e, "at"),         &at);
            json_get_i64(json_obj_get(e, "expires_at"), &exp);
            sch_mode_t m;
            if (!id || !sch_mode_parse(md, &m)) continue;
            grow_overrides(s);
            if (s->n_overrides >= s->cap_overrides) continue;
            sch_override_t *o = &s->overrides[s->n_overrides++];
            memset(o, 0, sizeof(*o));
            strncpy(o->id, id, sizeof(o->id) - 1);
            o->at         = at;
            o->expires_at = exp;
            o->mode       = m;
            if (reason) strncpy(o->reason, reason, sizeof(o->reason) - 1);
        }
    }

    json_val_free(v);
    return 0;
}

static int load_grants_file(wg_schedule_t *s) {
    if (!s->grants_path[0]) return 0;
    size_t n = 0;
    char *buf = read_small_file(s->grants_path, 64 * 1024, &n);
    if (!buf) return 0;
    const char *err = NULL;
    json_val_t *v = json_parse(buf, n, &err);
    free(buf);
    if (!v) {
        LOG_W("grants: parse %s: %s", s->grants_path, err ? err : "?");
        return -1;
    }
    if (v->type != JV_ARR) { json_val_free(v); return -1; }
    for (size_t i = 0; i < v->u.arr.n; i++) {
        const json_val_t *e = &v->u.arr.items[i];
        if (e->type != JV_OBJ) continue;
        const char *key = NULL, *reason = NULL;
        int64_t until = 0;
        json_get_str(json_obj_get(e, "key"),    &key);
        json_get_str(json_obj_get(e, "reason"), &reason);
        json_get_i64(json_obj_get(e, "until"),  &until);
        if (!key) continue;
        grow_grants(s);
        if (s->n_grants >= s->cap_grants) continue;
        sch_grant_t *g = &s->grants[s->n_grants++];
        memset(g, 0, sizeof(*g));
        strncpy(g->key, key, sizeof(g->key) - 1);
        g->until = until;
        if (reason) strncpy(g->reason, reason, sizeof(g->reason) - 1);
    }
    json_val_free(v);
    return 0;
}

int schedule_load(wg_schedule_t *s) {
    if (!s) return -1;
    apply_defaults(s);
    s->n_overrides = 0;
    s->n_grants    = 0;
    load_schedule_file(s);
    load_grants_file(s);
    s->dirty_schedule = false;
    s->dirty_grants   = false;
    return 0;
}

/* ---------------------------- save --------------------------------- */

static int save_schedule_file(wg_schedule_t *s) {
    if (!s->schedule_path[0]) return 0;
    json_out_t j;
    json_out_init(&j);
    json_obj_begin(&j);

    json_key(&j, "base");
    json_arr_begin(&j);
    for (size_t i = 0; i < s->n_base; i++) {
        char wd[8], hm[5];
        format_wdays_mask(s->base[i].wdays_mask, wd);
        format_hhmm(s->base[i].hhmm, hm);
        json_obj_begin(&j);
        json_kstr(&j, "wdays", wd);
        json_kstr(&j, "hhmm",  hm);
        json_kstr(&j, "mode",  sch_mode_name(s->base[i].mode));
        json_obj_end(&j);
    }
    json_arr_end(&j);

    json_key(&j, "overrides");
    json_arr_begin(&j);
    for (size_t i = 0; i < s->n_overrides; i++) {
        const sch_override_t *o = &s->overrides[i];
        json_obj_begin(&j);
        json_kstr(&j, "id",   o->id);
        json_ki64(&j, "at",   o->at);
        if (o->expires_at) json_ki64(&j, "expires_at", o->expires_at);
        json_kstr(&j, "mode", sch_mode_name(o->mode));
        if (o->reason[0]) json_kstr(&j, "reason", o->reason);
        json_obj_end(&j);
    }
    json_arr_end(&j);

    json_obj_end(&j);
    int rc = atomic_write(s->schedule_path,
                          j.buf ? j.buf : "{}",
                          j.buf ? j.len : 2);
    json_out_free(&j);
    return rc;
}

static int save_grants_file(wg_schedule_t *s) {
    if (!s->grants_path[0]) return 0;
    json_out_t j;
    json_out_init(&j);
    json_arr_begin(&j);
    for (size_t i = 0; i < s->n_grants; i++) {
        const sch_grant_t *g = &s->grants[i];
        json_obj_begin(&j);
        json_kstr(&j, "key",   g->key);
        json_ki64(&j, "until", g->until);
        if (g->reason[0]) json_kstr(&j, "reason", g->reason);
        json_obj_end(&j);
    }
    json_arr_end(&j);
    int rc = atomic_write(s->grants_path,
                          j.buf ? j.buf : "[]",
                          j.buf ? j.len : 2);
    json_out_free(&j);
    return rc;
}

int schedule_save(wg_schedule_t *s) {
    int rc = 0;
    if (s->dirty_schedule) { rc |= save_schedule_file(s); s->dirty_schedule = false; }
    if (s->dirty_grants)   { rc |= save_grants_file(s);   s->dirty_grants   = false; }
    return rc;
}

/* -------------------- base-schedule evaluation --------------------- */

/* Find the wall-clock epoch of the most recent occurrence of
 * (mask, hhmm) at or before `now_wall`. Returns 0 if mask is empty. */
static int64_t base_prev_occurrence(uint8_t mask, uint16_t hhmm, int64_t now_wall) {
    if (mask == 0) return 0;
    for (int offset = 0; offset < 8; offset++) {
        time_t t = (time_t)(now_wall - (int64_t)offset * 86400);
        struct tm tm;
        localtime_r(&t, &tm);
        uint8_t bit = (uint8_t)(1u << tm.tm_wday);
        if (!(mask & bit)) continue;
        tm.tm_hour  = hhmm / 100;
        tm.tm_min   = hhmm % 100;
        tm.tm_sec   = 0;
        tm.tm_isdst = -1;
        int64_t cand = (int64_t)mktime(&tm);
        if (cand <= now_wall) return cand;
    }
    return 0;
}

/* Find the wall-clock epoch of the next occurrence of (mask, hhmm) strictly
 * after `now_wall`. Returns 0 if mask is empty. */
static int64_t base_next_occurrence(uint8_t mask, uint16_t hhmm, int64_t now_wall) {
    if (mask == 0) return 0;
    for (int offset = 0; offset < 8; offset++) {
        time_t t = (time_t)(now_wall + (int64_t)offset * 86400);
        struct tm tm;
        localtime_r(&t, &tm);
        uint8_t bit = (uint8_t)(1u << tm.tm_wday);
        if (!(mask & bit)) continue;
        tm.tm_hour  = hhmm / 100;
        tm.tm_min   = hhmm % 100;
        tm.tm_sec   = 0;
        tm.tm_isdst = -1;
        int64_t cand = (int64_t)mktime(&tm);
        if (cand > now_wall) return cand;
    }
    return 0;
}

static bool base_mode_at(const wg_schedule_t *s, int64_t now_wall,
                         sch_mode_t *out_mode, int64_t *out_at) {
    int64_t best_at = 0;
    sch_mode_t best_mode = SCH_MODE_OPEN;
    bool any = false;
    for (size_t i = 0; i < s->n_base; i++) {
        int64_t at = base_prev_occurrence(s->base[i].wdays_mask,
                                          s->base[i].hhmm, now_wall);
        if (at == 0) continue;
        if (!any || at > best_at) {
            best_at   = at;
            best_mode = s->base[i].mode;
            any       = true;
        }
    }
    if (out_mode) *out_mode = best_mode;
    if (out_at)   *out_at   = best_at;
    return any;
}

/* -------------------- effective mode ------------------------------ */

sch_mode_t schedule_effective_mode(const wg_schedule_t *s, int64_t now_wall,
                                   int64_t *next_transition_out) {
    sch_mode_t base_mode;
    int64_t    base_at;
    bool have_base = base_mode_at(s, now_wall, &base_mode, &base_at);
    if (!have_base) base_mode = SCH_MODE_OPEN;

    /* Find the dominant active override (largest at <= now, not expired). */
    sch_mode_t mode = base_mode;
    int64_t    override_at = 0;
    bool       override_active = false;
    for (size_t i = 0; i < s->n_overrides; i++) {
        const sch_override_t *o = &s->overrides[i];
        if (o->at > now_wall) continue;
        if (o->expires_at && o->expires_at <= now_wall) continue;
        if (!override_active || o->at > override_at) {
            override_active = true;
            override_at     = o->at;
            mode            = o->mode;
        }
    }

    if (next_transition_out) {
        int64_t best = 0;
        /* nearest base transition after now */
        for (size_t i = 0; i < s->n_base; i++) {
            int64_t t = base_next_occurrence(s->base[i].wdays_mask,
                                             s->base[i].hhmm, now_wall);
            if (t && (best == 0 || t < best)) best = t;
        }
        /* pending / expiring overrides */
        for (size_t i = 0; i < s->n_overrides; i++) {
            const sch_override_t *o = &s->overrides[i];
            if (o->at > now_wall) {
                if (best == 0 || o->at < best) best = o->at;
            }
            if (o->expires_at && o->expires_at > now_wall) {
                if (best == 0 || o->expires_at < best) best = o->expires_at;
            }
        }
        *next_transition_out = best;
    }

    return mode;
}

/* ------------------------------ tick ------------------------------- */

void schedule_tick(wg_schedule_t *s, int64_t now_wall) {
    if (!s) return;
    /* prune overrides whose expires_at has passed (non-zero and <= now) */
    size_t w = 0;
    for (size_t r = 0; r < s->n_overrides; r++) {
        const sch_override_t *o = &s->overrides[r];
        if (o->expires_at && o->expires_at <= now_wall) {
            s->dirty_schedule = true;
            continue;
        }
        if (w != r) s->overrides[w] = *o;
        w++;
    }
    s->n_overrides = w;

    /* prune expired grants */
    w = 0;
    for (size_t r = 0; r < s->n_grants; r++) {
        const sch_grant_t *g = &s->grants[r];
        if (g->until <= now_wall) {
            s->dirty_grants = true;
            continue;
        }
        if (w != r) s->grants[w] = *g;
        w++;
    }
    s->n_grants = w;

    schedule_save(s);
}

/* ---------------------------- overrides --------------------------- */

static void make_id(wg_schedule_t *s, char *out, size_t cap) {
    s->id_counter++;
    snprintf(out, cap, "ov_%llx_%llx",
             (unsigned long long)time(NULL),
             (unsigned long long)s->id_counter);
}

int schedule_override_add(wg_schedule_t *s, int64_t at, sch_mode_t mode,
                          int64_t expires_at, const char *reason,
                          char *id_out, size_t cap) {
    if (!s) return -1;
    if (cap < 24) return -1;
    if (s->n_overrides >= OVERRIDES_MAX) {
        LOG_W("schedule: overrides at cap (%d); refusing add", OVERRIDES_MAX);
        return -1;
    }
    grow_overrides(s);
    if (s->n_overrides >= s->cap_overrides) return -1;
    sch_override_t *o = &s->overrides[s->n_overrides++];
    memset(o, 0, sizeof(*o));
    make_id(s, o->id, sizeof(o->id));
    o->at         = at;
    o->expires_at = expires_at;
    o->mode       = mode;
    if (reason) strncpy(o->reason, reason, sizeof(o->reason) - 1);
    strncpy(id_out, o->id, cap - 1);
    id_out[cap - 1] = 0;
    s->dirty_schedule = true;
    schedule_save(s);
    return 0;
}

int schedule_override_remove(wg_schedule_t *s, const char *id) {
    if (!s || !id) return 0;
    for (size_t i = 0; i < s->n_overrides; i++) {
        if (strcmp(s->overrides[i].id, id) == 0) {
            memmove(&s->overrides[i], &s->overrides[i+1],
                    (s->n_overrides - i - 1) * sizeof(*s->overrides));
            s->n_overrides--;
            s->dirty_schedule = true;
            schedule_save(s);
            return 1;
        }
    }
    return 0;
}

/* ----------------------------- grants ----------------------------- */

static void canonicalise_grant_key(const wg_leases_t *leases, const char *key,
                                   char *out, size_t cap) {
    blocks_canonicalise(leases, key, out, cap);
}

int schedule_grant_add_until(wg_schedule_t *s, const wg_leases_t *leases,
                             const char *key, int64_t until_wall,
                             const char *reason) {
    if (!s || !key) return 0;
    int64_t now = (int64_t)time(NULL);
    if (until_wall <= now) return 0;
    char canon[64];
    canonicalise_grant_key(leases, key, canon, sizeof(canon));

    /* update in place if an entry for this key already exists */
    for (size_t i = 0; i < s->n_grants; i++) {
        if (strcmp(s->grants[i].key, canon) == 0) {
            s->grants[i].until = until_wall;
            s->grants[i].reason[0] = 0;
            if (reason) strncpy(s->grants[i].reason, reason,
                                sizeof(s->grants[i].reason) - 1);
            s->dirty_grants = true;
            schedule_save(s);
            return 1;
        }
    }
    if (s->n_grants >= GRANTS_MAX) {
        LOG_W("schedule: grants at cap (%d); refusing add", GRANTS_MAX);
        return 0;
    }
    grow_grants(s);
    if (s->n_grants >= s->cap_grants) return 0;
    sch_grant_t *g = &s->grants[s->n_grants++];
    memset(g, 0, sizeof(*g));
    size_t kn = strnlen(canon, sizeof(g->key) - 1);
    memcpy(g->key, canon, kn);
    g->key[kn] = 0;
    g->until = until_wall;
    if (reason) strncpy(g->reason, reason, sizeof(g->reason) - 1);
    s->dirty_grants = true;
    schedule_save(s);
    return 1;
}

int schedule_grant_add(wg_schedule_t *s, const wg_leases_t *leases,
                       const char *key, int minutes, const char *reason) {
    if (minutes <= 0) return 0;
    int64_t until = (int64_t)time(NULL) + (int64_t)minutes * 60;
    return schedule_grant_add_until(s, leases, key, until, reason);
}

int schedule_grant_remove(wg_schedule_t *s, const wg_leases_t *leases,
                          const char *key) {
    if (!s || !key) return 0;
    char canon[64];
    canonicalise_grant_key(leases, key, canon, sizeof(canon));
    for (size_t i = 0; i < s->n_grants; i++) {
        if (strcmp(s->grants[i].key, canon) == 0) {
            memmove(&s->grants[i], &s->grants[i+1],
                    (s->n_grants - i - 1) * sizeof(*s->grants));
            s->n_grants--;
            s->dirty_grants = true;
            schedule_save(s);
            return 1;
        }
    }
    return 0;
}

size_t schedule_active_grant_ips(const wg_schedule_t *s,
                                 const wg_leases_t *leases,
                                 int64_t now_wall,
                                 uint32_t *out, size_t cap) {
    if (!s || !out || cap == 0) return 0;
    size_t n = 0;
    for (size_t i = 0; i < s->n_grants && n < cap; i++) {
        if (s->grants[i].until <= now_wall) continue;
        uint32_t ip;
        if (!blocks_resolve_ip(leases, s->grants[i].key, &ip)) continue;
        bool dup = false;
        for (size_t k = 0; k < n; k++) if (out[k] == ip) { dup = true; break; }
        if (dup) continue;
        out[n++] = ip;
    }
    return n;
}

bool schedule_grant_active_ip(const wg_schedule_t *s, const wg_leases_t *leases,
                              uint32_t ip, int64_t now_wall) {
    if (!s) return false;
    for (size_t i = 0; i < s->n_grants; i++) {
        if (s->grants[i].until <= now_wall) continue;
        uint32_t kip;
        if (!blocks_resolve_ip(leases, s->grants[i].key, &kip)) continue;
        if (kip == ip) return true;
    }
    return false;
}

/* ---------------------------- JSON dump --------------------------- */

void schedule_dump_json(const wg_schedule_t *s, int64_t now_wall,
                        json_out_t *j) {
    json_obj_begin(j);
    int64_t next = 0;
    sch_mode_t cur = schedule_effective_mode(s, now_wall, &next);
    json_kstr(j, "mode", sch_mode_name(cur));
    json_ki64(j, "now",  now_wall);
    if (next) json_ki64(j, "next_transition", next);
    else      json_knull(j, "next_transition");

    json_key(j, "base");
    json_arr_begin(j);
    for (size_t i = 0; i < s->n_base; i++) {
        char wd[8], hm[5];
        format_wdays_mask(s->base[i].wdays_mask, wd);
        format_hhmm(s->base[i].hhmm, hm);
        json_obj_begin(j);
        json_kstr(j, "wdays", wd);
        json_kstr(j, "hhmm",  hm);
        json_kstr(j, "mode",  sch_mode_name(s->base[i].mode));
        json_obj_end(j);
    }
    json_arr_end(j);

    json_key(j, "overrides");
    json_arr_begin(j);
    for (size_t i = 0; i < s->n_overrides; i++) {
        const sch_override_t *o = &s->overrides[i];
        json_obj_begin(j);
        json_kstr(j, "id",   o->id);
        json_ki64(j, "at",   o->at);
        if (o->expires_at) json_ki64(j, "expires_at", o->expires_at);
        json_kstr(j, "mode", sch_mode_name(o->mode));
        if (o->reason[0]) json_kstr(j, "reason", o->reason);
        bool active = (o->at <= now_wall) &&
                      (o->expires_at == 0 || o->expires_at > now_wall);
        json_kbool(j, "active", active);
        json_obj_end(j);
    }
    json_arr_end(j);

    json_key(j, "grants");
    json_arr_begin(j);
    for (size_t i = 0; i < s->n_grants; i++) {
        const sch_grant_t *g = &s->grants[i];
        json_obj_begin(j);
        json_kstr(j, "key",   g->key);
        json_ki64(j, "until", g->until);
        if (g->reason[0]) json_kstr(j, "reason", g->reason);
        json_obj_end(j);
    }
    json_arr_end(j);

    json_obj_end(j);
}

/* --------------------- effective block-set ------------------------ */

void schedule_compute_blockset(const wg_schedule_t *s,
                               const wg_supervisor_t *sup,
                               const wg_blocks_t *blocks,
                               const wg_leases_t *leases,
                               const wg_cfg_t *cfg,
                               int64_t now_wall,
                               wg_block_set_t *out) {
    wg_block_set_init(out);
    sch_mode_t mode = s ? schedule_effective_mode(s, now_wall, NULL)
                        : SCH_MODE_OPEN;

    /* Mode-driven per-host DROPs: only supervised contributes (its
     * triggered-device list). Closed mode does not enumerate the
     * dhcp-range here — iptables_reconcile applies a single
     * `-i <lan> -j DROP` rule that covers the whole LAN. */
    if (mode == SCH_MODE_SUPERVISED && sup && leases) {
        uint32_t trig[256];
        size_t n = supervisor_triggered_ips(sup, leases, now_wall, trig,
                                            sizeof(trig) / sizeof(*trig));
        for (size_t i = 0; i < n; i++) {
            uint32_t ip = trig[i];
            if (s && schedule_grant_active_ip(s, leases, ip, now_wall)) continue;
            wg_block_set_add(out, ip);
        }
    }

    /* Permanent blocks from blocks.json — these always apply. */
    if (blocks) {
        for (size_t i = 0; i < blocks->n; i++) {
            uint32_t ip;
            if (!blocks_resolve_ip(leases, blocks->items[i].key, &ip)) continue;
            if (cfg && !ip_in_subnet(ip, cfg->net_addr, cfg->net_mask)) continue;
            if (s && schedule_grant_active_ip(s, leases, ip, now_wall)) continue;
            if (wg_block_set_has(out, ip)) continue;
            wg_block_set_add(out, ip);
        }
    }
}
