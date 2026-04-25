#include "pins.h"
#include "log.h"
#include "util.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define PINS_MAX 256

typedef struct {
    char       key[64];
    sch_mode_t mode;
    int64_t    until;
    char       reason[64];
} wg_pin_t;

struct wg_pins {
    wg_pin_t  *items;
    size_t     n, cap;

    char       path     [256];
    char       ipset_bin[96];
    bool       dirty;
};

static const char *pin_set_name(sch_mode_t m) {
    switch (m) {
        case SCH_MODE_OPEN:     return "wgate_pin_open";
        case SCH_MODE_CLOSED:   return "wgate_pin_closed";
        case SCH_MODE_FILTERED: return "wgate_pin_filt";
    }
    return NULL;
}

/* ------------------------------ ipset ----------------------------- */

static int run_ipset_argv(const char *bin, char *const argv[]) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, 1); if (devnull > 2) close(devnull); }
        execv(bin, argv);
        _exit(127);
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) { /* retry on EINTR */ }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
}

static void ipset_flush(const wg_pins_t *p, const char *set_name) {
    if (!p->ipset_bin[0]) return;
    char *argv[] = {
        (char*)p->ipset_bin, (char*)"flush", (char*)set_name, NULL
    };
    int rc = run_ipset_argv(p->ipset_bin, argv);
    if (rc != 0) LOG_W("ipset flush %s: rc=%d", set_name, rc);
}

static void ipset_add(const wg_pins_t *p, const char *set_name, uint32_t ip) {
    if (!p->ipset_bin[0] || ip == 0) return;
    char ipbuf[16];
    ip_format(ip, ipbuf);
    char *argv[] = {
        (char*)p->ipset_bin, (char*)"add", (char*)set_name,
        ipbuf, (char*)"-exist", NULL
    };
    int rc = run_ipset_argv(p->ipset_bin, argv);
    if (rc != 0) LOG_W("ipset add %s %s: rc=%d", set_name, ipbuf, rc);
}

/* --------------------------- new/free ---------------------------- */

wg_pins_t *pins_new(const char *path, const char *ipset_bin) {
    wg_pins_t *p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    if (path)      strncpy(p->path,      path,      sizeof(p->path)      - 1);
    if (ipset_bin) strncpy(p->ipset_bin, ipset_bin, sizeof(p->ipset_bin) - 1);
    return p;
}

void pins_free(wg_pins_t *p) {
    if (!p) return;
    free(p->items);
    free(p);
}

/* ---------------------------- storage ---------------------------- */

static int grow(wg_pins_t *p) {
    if (p->n < p->cap) return 0;
    if (p->cap >= PINS_MAX) return -1;
    size_t nc = p->cap ? p->cap * 2 : 16;
    if (nc > PINS_MAX) nc = PINS_MAX;
    wg_pin_t *n = realloc(p->items, nc * sizeof(*n));
    if (!n) return -1;
    memset(n + p->cap, 0, (nc - p->cap) * sizeof(*n));
    p->items = n;
    p->cap   = nc;
    return 0;
}

static int find_idx_by_canon(const wg_pins_t *p, const char *canon) {
    for (size_t i = 0; i < p->n; i++) {
        if (strcmp(p->items[i].key, canon) == 0) return (int)i;
    }
    return -1;
}

int pins_load(wg_pins_t *p) {
    if (!p) return -1;
    p->n = 0;
    if (!p->path[0]) return 0;
    size_t n = 0;
    char *buf = read_small_file(p->path, 64 * 1024, &n);
    if (!buf) return 0;
    const char *err = NULL;
    json_val_t *v = json_parse(buf, n, &err);
    free(buf);
    if (!v) {
        LOG_W("pins: parse %s: %s", p->path, err ? err : "?");
        return -1;
    }
    if (v->type != JV_ARR) { json_val_free(v); return -1; }

    for (size_t i = 0; i < v->u.arr.n; i++) {
        const json_val_t *e = &v->u.arr.items[i];
        if (e->type != JV_OBJ) continue;
        const char *key = NULL, *mode_str = NULL, *reason = NULL;
        int64_t until = 0;
        json_get_str(json_obj_get(e, "key"),    &key);
        json_get_str(json_obj_get(e, "mode"),   &mode_str);
        json_get_i64(json_obj_get(e, "until"),  &until);
        json_get_str(json_obj_get(e, "reason"), &reason);
        if (!key || !mode_str) continue;
        sch_mode_t m;
        if (!sch_mode_parse(mode_str, &m)) continue;
        if (grow(p) < 0) break;
        if (p->n >= p->cap) break;
        wg_pin_t *it = &p->items[p->n++];
        memset(it, 0, sizeof(*it));
        strncpy(it->key, key, sizeof(it->key) - 1);
        it->mode  = m;
        it->until = until;
        if (reason) strncpy(it->reason, reason, sizeof(it->reason) - 1);
    }
    json_val_free(v);
    LOG_I("pins: loaded %zu entr%s from %s",
          p->n, p->n == 1 ? "y" : "ies", p->path);
    return 0;
}

int pins_save(wg_pins_t *p) {
    if (!p || !p->path[0]) return 0;
    if (!p->dirty) return 0;
    json_out_t j;
    json_out_init(&j);
    json_arr_begin(&j);
    for (size_t i = 0; i < p->n; i++) {
        const wg_pin_t *it = &p->items[i];
        json_obj_begin(&j);
        json_kstr(&j, "key",   it->key);
        json_kstr(&j, "mode",  sch_mode_name(it->mode));
        json_ki64(&j, "until", it->until);
        if (it->reason[0]) json_kstr(&j, "reason", it->reason);
        json_obj_end(&j);
    }
    json_arr_end(&j);
    int rc = atomic_write(p->path,
                          j.buf ? j.buf : "[]",
                          j.buf ? j.len : 2);
    json_out_free(&j);
    if (rc == 0) p->dirty = false;
    return rc;
}

/* ---------------------------- mutators --------------------------- */

int pins_set(wg_pins_t *p, const wg_leases_t *leases, const char *key,
             sch_mode_t mode, int64_t until_wall, const char *reason) {
    if (!p || !key || !*key) return 0;
    char canon[64];
    leases_canon_key(leases, key, canon, sizeof(canon));
    if (!canon[0]) return 0;

    int idx = find_idx_by_canon(p, canon);
    if (idx >= 0) {
        wg_pin_t *it = &p->items[idx];
        it->mode  = mode;
        it->until = until_wall;
        memset(it->reason, 0, sizeof(it->reason));
        if (reason) strncpy(it->reason, reason, sizeof(it->reason) - 1);
        p->dirty = true;
        pins_save(p);
        return 1;
    }

    if (p->n >= PINS_MAX) {
        LOG_W("pins: at cap (%d); refusing to add %s", PINS_MAX, canon);
        return 0;
    }
    if (grow(p) < 0) return 0;
    wg_pin_t *it = &p->items[p->n++];
    memset(it, 0, sizeof(*it));
    strncpy(it->key, canon, sizeof(it->key) - 1);
    it->mode  = mode;
    it->until = until_wall;
    if (reason) strncpy(it->reason, reason, sizeof(it->reason) - 1);
    p->dirty = true;
    pins_save(p);
    return 1;
}

int pins_remove(wg_pins_t *p, const wg_leases_t *leases, const char *key) {
    if (!p || !key) return 0;
    char canon[64];
    leases_canon_key(leases, key, canon, sizeof(canon));
    int idx = find_idx_by_canon(p, canon);
    if (idx < 0) return 0;
    memmove(&p->items[idx], &p->items[idx + 1],
            (p->n - (size_t)idx - 1) * sizeof(*p->items));
    p->n--;
    memset(&p->items[p->n], 0, sizeof(p->items[p->n]));
    p->dirty = true;
    pins_save(p);
    return 1;
}

/* ---------------------------- queries ---------------------------- */

sch_mode_t pins_for_ip(const wg_pins_t *p, const wg_leases_t *leases,
                       uint32_t ip, int64_t now_wall, bool *out_pinned) {
    if (out_pinned) *out_pinned = false;
    if (!p || ip == 0) return SCH_MODE_OPEN;
    for (size_t i = 0; i < p->n; i++) {
        const wg_pin_t *it = &p->items[i];
        if (it->until <= now_wall) continue;
        uint32_t kip;
        if (!leases_resolve_ip(leases, it->key, &kip)) continue;
        if (kip == ip) {
            if (out_pinned) *out_pinned = true;
            return it->mode;
        }
    }
    return SCH_MODE_OPEN;
}

void pins_tick(wg_pins_t *p, int64_t now_wall) {
    if (!p) return;
    size_t w = 0;
    bool changed = false;
    for (size_t r = 0; r < p->n; r++) {
        if (p->items[r].until <= now_wall) { changed = true; continue; }
        if (w != r) p->items[w] = p->items[r];
        w++;
    }
    if (changed) {
        p->n = w;
        p->dirty = true;
        pins_save(p);
    }
}

void pins_dump_to_ipsets(const wg_pins_t *p, const wg_leases_t *leases,
                         int64_t now_wall) {
    if (!p) return;
    /* Always flush all three sets, even when empty — guarantees the
     * kernel state matches our in-memory truth after every reconcile. */
    ipset_flush(p, "wgate_pin_open");
    ipset_flush(p, "wgate_pin_closed");
    ipset_flush(p, "wgate_pin_filt");

    for (size_t i = 0; i < p->n; i++) {
        const wg_pin_t *it = &p->items[i];
        if (it->until <= now_wall) continue;
        uint32_t ip;
        if (!leases_resolve_ip(leases, it->key, &ip)) continue;
        const char *set_name = pin_set_name(it->mode);
        if (!set_name) continue;
        ipset_add(p, set_name, ip);
    }
}

size_t pins_count(const wg_pins_t *p, int64_t now_wall) {
    if (!p) return 0;
    size_t n = 0;
    for (size_t i = 0; i < p->n; i++) if (p->items[i].until > now_wall) n++;
    return n;
}

void pins_dump_json(const wg_pins_t *p, int64_t now_wall, json_out_t *j) {
    json_arr_begin(j);
    if (p) for (size_t i = 0; i < p->n; i++) {
        const wg_pin_t *it = &p->items[i];
        if (it->until <= now_wall) continue;
        json_obj_begin(j);
        json_kstr(j, "key",   it->key);
        json_kstr(j, "mode",  sch_mode_name(it->mode));
        json_ki64(j, "until", it->until);
        if (it->reason[0]) json_kstr(j, "reason", it->reason);
        json_obj_end(j);
    }
    json_arr_end(j);
}

size_t pins_active(const wg_pins_t *p, int64_t now_wall,
                   wg_pin_view_t *out, size_t cap) {
    if (!p || !out || cap == 0) return 0;
    size_t n = 0;
    for (size_t i = 0; i < p->n && n < cap; i++) {
        const wg_pin_t *it = &p->items[i];
        if (it->until <= now_wall) continue;
        out[n].key    = it->key;
        out[n].mode   = it->mode;
        out[n].until  = it->until;
        out[n].reason = it->reason[0] ? it->reason : NULL;
        n++;
    }
    return n;
}
