#include "schedule.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Pinned timezone: Asia/Shanghai is UTC+8, no DST — predictable. */

static int64_t mk(int y, int mo, int d, int h, int mi) {
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    tm.tm_year  = y - 1900;
    tm.tm_mon   = mo - 1;
    tm.tm_mday  = d;
    tm.tm_hour  = h;
    tm.tm_min   = mi;
    tm.tm_isdst = -1;
    return (int64_t)mktime(&tm);
}

static int wday_of(int64_t ts) {
    time_t t = (time_t)ts;
    struct tm tm;
    localtime_r(&t, &tm);
    return tm.tm_wday;
}

#define EXPECT_MODE(sched, ts, want) do {                                    \
    sch_mode_t got = schedule_effective_mode((sched), (ts), NULL);           \
    if (got != (want)) {                                                     \
        fprintf(stderr, "FAIL %s:%d ts=%lld wday=%d mode=%s want=%s\n",      \
                __FILE__, __LINE__, (long long)(ts), wday_of(ts),            \
                sch_mode_name(got), sch_mode_name(want));                    \
        exit(1);                                                             \
    }                                                                        \
} while (0)

int main(void) {
    setenv("TZ", "Asia/Shanghai", 1);
    tzset();

    wg_schedule_t *s = schedule_new(NULL, NULL);
    assert(s);
    schedule_load(s);                /* applies hard-coded defaults */

    /* Verify weekday anchors for our test week (choose any week).
     * 2026-04-19 is a Sunday.  */
    assert(wday_of(mk(2026,4,19, 12,0)) == 0);  /* Sun */
    assert(wday_of(mk(2026,4,20, 12,0)) == 1);  /* Mon */
    assert(wday_of(mk(2026,4,21, 12,0)) == 2);  /* Tue */
    assert(wday_of(mk(2026,4,22, 12,0)) == 3);  /* Wed */
    assert(wday_of(mk(2026,4,23, 12,0)) == 4);  /* Thu */
    assert(wday_of(mk(2026,4,24, 12,0)) == 5);  /* Fri */
    assert(wday_of(mk(2026,4,25, 12,0)) == 6);  /* Sat */

    /* Base schedule expectations (all Mon = 2026-04-20 unless noted). */
    EXPECT_MODE(s, mk(2026,4,20, 6,59),  SCH_MODE_CLOSED);     /* Sun 22:30 closed */
    EXPECT_MODE(s, mk(2026,4,20, 7,0),   SCH_MODE_SUPERVISED); /* Mon 07:00 */
    EXPECT_MODE(s, mk(2026,4,20, 17,59), SCH_MODE_SUPERVISED);
    EXPECT_MODE(s, mk(2026,4,20, 18,0),  SCH_MODE_OPEN);
    EXPECT_MODE(s, mk(2026,4,20, 22,29), SCH_MODE_OPEN);
    EXPECT_MODE(s, mk(2026,4,20, 22,30), SCH_MODE_CLOSED);     /* Mon 22:30 (in 0x1B) */

    /* Tuesday: 22:30 does NOT apply (Tue not in 0x1B); closes at 23:30. */
    EXPECT_MODE(s, mk(2026,4,21, 22,30), SCH_MODE_OPEN);
    EXPECT_MODE(s, mk(2026,4,21, 23,29), SCH_MODE_OPEN);
    EXPECT_MODE(s, mk(2026,4,21, 23,30), SCH_MODE_CLOSED);     /* Tue 23:30 (in 0x64) */
    EXPECT_MODE(s, mk(2026,4,22, 2,0),   SCH_MODE_CLOSED);     /* still Tue-night bedtime */
    EXPECT_MODE(s, mk(2026,4,22, 6,59),  SCH_MODE_CLOSED);
    EXPECT_MODE(s, mk(2026,4,22, 7,0),   SCH_MODE_SUPERVISED); /* Wed 07:00 */

    /* Overrides: insert Tue 20:00 → closed, expires Tue 21:00. */
    int64_t ov_at  = mk(2026,4,21, 20,0);
    int64_t ov_exp = mk(2026,4,21, 21,0);
    char id[24];
    int rc = schedule_override_add(s, ov_at, SCH_MODE_CLOSED, ov_exp, "test",
                                   id, sizeof(id));
    assert(rc == 0);

    EXPECT_MODE(s, mk(2026,4,21, 19,59), SCH_MODE_OPEN);       /* before override */
    EXPECT_MODE(s, mk(2026,4,21, 20,0),  SCH_MODE_CLOSED);     /* at override */
    EXPECT_MODE(s, mk(2026,4,21, 20,30), SCH_MODE_CLOSED);     /* during */
    EXPECT_MODE(s, mk(2026,4,21, 21,0),  SCH_MODE_OPEN);       /* override expired */
    EXPECT_MODE(s, mk(2026,4,21, 21,30), SCH_MODE_OPEN);

    /* schedule_tick should prune the expired override. */
    schedule_tick(s, mk(2026,4,21, 22,0));
    rc = schedule_override_remove(s, id);
    assert(rc == 0 || rc == 1);   /* already gone is fine */

    /* Grants: add a 5-minute grant for a raw IP. */
    wg_leases_t leases;
    memset(&leases, 0, sizeof(leases));
    rc = schedule_grant_add(s, &leases, "10.6.6.99", 5, "homework");
    assert(rc == 1);
    int64_t now = mk(2026,4,20, 12,0);
    assert(schedule_grant_active_ip(s, &leases, 0x0A060663, now) == true);  /* 10.6.6.99 */
    assert(schedule_grant_active_ip(s, &leases, 0x0A060664, now) == false); /* 10.6.6.100 */

    schedule_free(s);
    printf("OK test_schedule\n");
    return 0;
}
