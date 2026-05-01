#include "seen_db.h"
#include "json.h"
#include "log.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* Hard cap so a hostile DHCP storm can't grow the file unbounded. The
 * map is linear-scanned on every observe(), so the cap also keeps the
 * O(N) scan cost bounded. */
#define SEEN_DB_MAX 4096

typedef struct {
    uint8_t mac[6];
    int64_t first_seen;
    int64_t last_seen;
} row_t;

struct wg_seen_db {
    char    path[256];
    row_t  *rows;
    size_t  n;
    size_t  cap;
    bool    dirty;
};

static int find_idx(const wg_seen_db_t *db, const uint8_t mac[6]) {
    for (size_t i = 0; i < db->n; i++) {
        if (memcmp(db->rows[i].mac, mac, 6) == 0) return (int)i;
    }
    return -1;
}

static int grow(wg_seen_db_t *db) {
    if (db->n < db->cap) return 0;
    if (db->cap >= SEEN_DB_MAX) return -1;
    size_t ncap = db->cap ? db->cap * 2 : 32;
    if (ncap > SEEN_DB_MAX) ncap = SEEN_DB_MAX;
    row_t *nr = realloc(db->rows, ncap * sizeof(*nr));
    if (!nr) return -1;
    db->rows = nr;
    db->cap  = ncap;
    return 0;
}

static void load_from_file(wg_seen_db_t *db) {
    if (!db->path[0]) return;
    size_t n = 0;
    char *buf = read_small_file(db->path, 1 << 20, &n);
    if (!buf) return;
    const char *err = NULL;
    json_val_t *v = json_parse(buf, n, &err);
    free(buf);
    if (!v) {
        LOG_W("seen_db: parse %s: %s", db->path, err ? err : "?");
        return;
    }
    if (v->type != JV_ARR) { json_val_free(v); return; }

    int truncated = 0;
    for (size_t i = 0; i < v->u.arr.n; i++) {
        const json_val_t *iv = &v->u.arr.items[i];
        if (iv->type != JV_OBJ) continue;
        const char *mac_s = NULL;
        int64_t fs = 0, ls = 0;
        json_get_str(json_obj_get(iv, "mac"),        &mac_s);
        json_get_i64(json_obj_get(iv, "first_seen"), &fs);
        json_get_i64(json_obj_get(iv, "last_seen"),  &ls);
        if (!mac_s) continue;
        uint8_t mac[6];
        if (!mac_parse(mac_s, mac)) continue;
        if (db->n >= SEEN_DB_MAX) { truncated = 1; break; }
        if (grow(db) < 0) break;
        memcpy(db->rows[db->n].mac, mac, 6);
        db->rows[db->n].first_seen = fs;
        db->rows[db->n].last_seen  = ls;
        db->n++;
    }
    json_val_free(v);
    if (truncated)
        LOG_W("seen_db: truncating on-disk table at %d rows", SEEN_DB_MAX);
    LOG_I("seen_db: loaded %zu host%s from %s",
          db->n, db->n == 1 ? "" : "s", db->path);
}

wg_seen_db_t *seen_db_open(const char *path) {
    wg_seen_db_t *db = calloc(1, sizeof(*db));
    if (!db) return NULL;
    if (path && *path) {
        size_t n = strlen(path);
        if (n >= sizeof(db->path)) n = sizeof(db->path) - 1;
        memcpy(db->path, path, n);
        db->path[n] = 0;
    }
    load_from_file(db);
    return db;
}

void seen_db_close(wg_seen_db_t *db) {
    if (!db) return;
    free(db->rows);
    free(db);
}

bool seen_db_get(const wg_seen_db_t *db, const uint8_t mac[6],
                 int64_t *first_seen, int64_t *last_seen) {
    if (!db) return false;
    int i = find_idx(db, mac);
    if (i < 0) return false;
    if (first_seen) *first_seen = db->rows[i].first_seen;
    if (last_seen)  *last_seen  = db->rows[i].last_seen;
    return true;
}

int seen_db_observe(wg_seen_db_t *db, const uint8_t mac[6], int64_t now) {
    if (!db) return 0;
    int i = find_idx(db, mac);
    if (i >= 0) {
        if (db->rows[i].last_seen != now) {
            db->rows[i].last_seen = now;
            db->dirty = true;
        }
        return 0;
    }
    if (db->n >= SEEN_DB_MAX) {
        char macbuf[18];
        mac_format(mac, macbuf);
        LOG_W("seen_db: at cap (%d), refusing to add %s", SEEN_DB_MAX, macbuf);
        return 0;
    }
    if (grow(db) < 0) return 0;
    memcpy(db->rows[db->n].mac, mac, 6);
    db->rows[db->n].first_seen = now;
    db->rows[db->n].last_seen  = now;
    db->n++;
    db->dirty = true;
    return 1;
}

bool seen_db_dirty(const wg_seen_db_t *db) {
    return db && db->dirty;
}

int seen_db_save(wg_seen_db_t *db) {
    if (!db || !db->path[0]) return 0;
    if (!db->dirty) return 0;

    /* Make sure the parent directory exists (e.g. /opt/wgatectl). */
    char parent[256];
    size_t pn = strlen(db->path);
    if (pn >= sizeof(parent)) return -1;
    memcpy(parent, db->path, pn + 1);
    char *slash = strrchr(parent, '/');
    if (slash && slash != parent) {
        *slash = 0;
        if (mkdir_p(parent, 0755) < 0) {
            /* mkdir failure is not necessarily fatal — atomic_write may
             * still succeed if some other process created the dir. */
        }
    }

    json_out_t j;
    json_out_init(&j);
    json_arr_begin(&j);
    for (size_t i = 0; i < db->n; i++) {
        char macbuf[18];
        mac_format(db->rows[i].mac, macbuf);
        json_obj_begin(&j);
        json_kstr(&j, "mac",        macbuf);
        json_ki64(&j, "first_seen", db->rows[i].first_seen);
        json_ki64(&j, "last_seen",  db->rows[i].last_seen);
        json_obj_end(&j);
    }
    json_arr_end(&j);
    int rc = atomic_write(db->path, j.buf ? j.buf : "[]",
                          j.buf ? j.len : 2);
    json_out_free(&j);
    if (rc == 0) db->dirty = false;
    return rc;
}
