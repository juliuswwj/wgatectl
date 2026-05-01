#include "leases.h"
#include "seen_db.h"
#include "util.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void w(const char *p, const char *s) {
    int rc = atomic_write(p, s, strlen(s));
    assert(rc == 0);
}

/* ----------------------- seen_db basics ------------------------ */

static void test_seen_db_basics(void) {
    char path[64];
    snprintf(path, sizeof(path), "/tmp/wgatectl_seen_db.%d.json", (int)getpid());
    unlink(path);

    uint8_t mac1[6] = { 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01 };
    uint8_t mac2[6] = { 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x02 };

    {
        wg_seen_db_t *db = seen_db_open(path);
        assert(db);
        int64_t fs = 0, ls = 0;
        assert(!seen_db_get(db, mac1, &fs, &ls));

        assert(seen_db_observe(db, mac1, 1000) == 1);   /* first time */
        assert(seen_db_observe(db, mac1, 2000) == 0);   /* bump */
        assert(seen_db_observe(db, mac2, 1500) == 1);

        assert(seen_db_get(db, mac1, &fs, &ls));
        assert(fs == 1000 && ls == 2000);
        assert(seen_db_get(db, mac2, &fs, &ls));
        assert(fs == 1500 && ls == 1500);

        assert(seen_db_dirty(db));
        assert(seen_db_save(db) == 0);
        assert(!seen_db_dirty(db));
        seen_db_close(db);
    }

    /* re-open: persistence */
    {
        wg_seen_db_t *db = seen_db_open(path);
        assert(db);
        int64_t fs = 0, ls = 0;
        assert(seen_db_get(db, mac1, &fs, &ls));
        assert(fs == 1000 && ls == 2000);

        /* bumping with same value is a no-op for dirty */
        assert(!seen_db_dirty(db));
        seen_db_observe(db, mac1, 2000);
        assert(!seen_db_dirty(db));
        seen_db_observe(db, mac1, 2500);
        assert(seen_db_dirty(db));
        seen_db_close(db);
    }

    unlink(path);
    printf("OK seen_db basics\n");
}

/* -------- leases_reload populates first/last_seen + diff -------- */

typedef struct {
    int  n_add, n_remove;
    char last_action[16];
    char last_mac[18];
    char last_ip[16];
    char last_name[64];
    char last_reason[16];
} cb_state_t;

static void on_change(void *arg, bool added, const uint8_t mac[6],
                      uint32_t ip, const char *name, const char *reason) {
    cb_state_t *s = arg;
    if (added) s->n_add++;
    else       s->n_remove++;
    strcpy(s->last_action, added ? "add" : "remove");
    mac_format(mac, s->last_mac);
    ip_format(ip, s->last_ip);
    strncpy(s->last_name, name ? name : "", sizeof(s->last_name) - 1);
    s->last_name[sizeof(s->last_name) - 1] = 0;
    strncpy(s->last_reason, reason ? reason : "",
            sizeof(s->last_reason) - 1);
    s->last_reason[sizeof(s->last_reason) - 1] = 0;
}

static void test_leases_diff_and_seen(void) {
    char db_path[64], lease_path[64], conf_path[64];
    snprintf(db_path,    sizeof(db_path),    "/tmp/wgctl_t_db.%d.json",
             (int)getpid());
    snprintf(lease_path, sizeof(lease_path), "/tmp/wgctl_t_lease.%d",
             (int)getpid());
    snprintf(conf_path,  sizeof(conf_path),  "/tmp/wgctl_t_conf.%d",
             (int)getpid());
    unlink(db_path); unlink(lease_path); unlink(conf_path);

    /* Empty conf, single lease initially. */
    w(conf_path, "");
    w(lease_path,
      "1700000000 aa:bb:cc:00:00:01 10.6.6.10 ipad *\n");

    wg_seen_db_t *db = seen_db_open(db_path);
    assert(db);

    wg_leases_t lt;
    leases_init(&lt);
    leases_set_seen_db(&lt, db);

    /* First reload: seeds prev, no callback wired yet, no diff events. */
    leases_reload(&lt, conf_path, lease_path, NULL);
    assert(lt.n == 1);
    assert(lt.items[0].first_seen > 0);
    assert(lt.items[0].last_seen  > 0);
    int64_t initial_first = lt.items[0].first_seen;

    /* Wire callback now. */
    cb_state_t st = {0};
    leases_set_change_cb(&lt, on_change, &st);

    /* Same lease file → no diff. */
    leases_reload(&lt, conf_path, lease_path, NULL);
    assert(st.n_add == 0 && st.n_remove == 0);
    assert(lt.items[0].first_seen == initial_first);  /* preserved */

    /* Add a new lease line; expect one "add". */
    w(lease_path,
      "1700000000 aa:bb:cc:00:00:01 10.6.6.10 ipad *\n"
      "1700000000 aa:bb:cc:00:00:02 10.6.6.11 phone *\n");
    leases_reload(&lt, conf_path, lease_path, NULL);
    assert(st.n_add    == 1);
    assert(st.n_remove == 0);
    assert(strcmp(st.last_action, "add") == 0);
    assert(strcmp(st.last_mac, "aa:bb:cc:00:00:02") == 0);
    assert(strcmp(st.last_ip, "10.6.6.11") == 0);
    assert(strcmp(st.last_name, "phone") == 0);

    /* Remove the second lease; expect one "remove" with reason="expired". */
    w(lease_path,
      "1700000000 aa:bb:cc:00:00:01 10.6.6.10 ipad *\n");
    leases_reload(&lt, conf_path, lease_path, NULL);
    assert(st.n_add    == 1);
    assert(st.n_remove == 1);
    assert(strcmp(st.last_action, "remove") == 0);
    assert(strcmp(st.last_mac, "aa:bb:cc:00:00:02") == 0);
    assert(strcmp(st.last_reason, "expired") == 0);

    /* Replace IP holder: same IP, new MAC. Expect remove(reason="replaced") +
     * add. */
    w(lease_path,
      "1700000000 aa:bb:cc:00:00:99 10.6.6.10 different *\n");
    leases_reload(&lt, conf_path, lease_path, NULL);
    assert(st.n_add    == 2);
    assert(st.n_remove == 2);
    /* Order is add-then-remove inside emit_diff, so last event is the
     * remove. The remove reason should be "replaced", not "expired". */
    assert(strcmp(st.last_action, "remove") == 0);
    assert(strcmp(st.last_reason, "replaced") == 0);

    /* Persistence: first_seen for the original mac1 should still be the
     * same value seeded on first reload. */
    int64_t fs = 0, ls = 0;
    uint8_t mac1[6] = { 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01 };
    assert(seen_db_get(db, mac1, &fs, &ls));
    assert(fs == initial_first);

    leases_free(&lt);
    seen_db_close(db);
    unlink(db_path); unlink(lease_path); unlink(conf_path);
    printf("OK leases diff + seen_db integration\n");
}

int main(void) {
    test_seen_db_basics();
    test_leases_diff_and_seen();
    printf("OK test_seen_db\n");
    return 0;
}
