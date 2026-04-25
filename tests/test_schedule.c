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

    wg_schedule_t *s = schedule_new(NULL);
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

    /* Base schedule expectations.
     * Default bedtimes: Sun/Mon/Wed/Thu 23:00, Tue 23:30, Sat/Sun 00:00. */

    /* Monday (2026-04-20): carries Sun-night closure until 07:00. */
    EXPECT_MODE(s, mk(2026,4,20, 6,59),  SCH_MODE_CLOSED);     /* still Sun bedtime */
    EXPECT_MODE(s, mk(2026,4,20, 7,0),   SCH_MODE_FILTERED); /* Mon 07:00 wakes */
    EXPECT_MODE(s, mk(2026,4,20, 17,59), SCH_MODE_FILTERED);
    EXPECT_MODE(s, mk(2026,4,20, 18,0),  SCH_MODE_OPEN);
    EXPECT_MODE(s, mk(2026,4,20, 22,59), SCH_MODE_OPEN);
    EXPECT_MODE(s, mk(2026,4,20, 23,0),  SCH_MODE_CLOSED);     /* Mon 23:00 (in 0x1B) */

    /* Tuesday (2026-04-21): 23:00 does NOT apply; closes at 23:30. */
    EXPECT_MODE(s, mk(2026,4,21, 23,0),  SCH_MODE_OPEN);
    EXPECT_MODE(s, mk(2026,4,21, 23,29), SCH_MODE_OPEN);
    EXPECT_MODE(s, mk(2026,4,21, 23,30), SCH_MODE_CLOSED);     /* Tue 23:30 */
    EXPECT_MODE(s, mk(2026,4,22, 2,0),   SCH_MODE_CLOSED);     /* still Tue-night bedtime */
    EXPECT_MODE(s, mk(2026,4,22, 6,59),  SCH_MODE_CLOSED);
    EXPECT_MODE(s, mk(2026,4,22, 7,0),   SCH_MODE_FILTERED); /* Wed 07:00 */

    /* Friday (2026-04-24) → Saturday: Fri has NO bedtime rule, stays open
     * past 23:00; Sat 00:00 closed triggers midnight. */
    EXPECT_MODE(s, mk(2026,4,24, 23,0),  SCH_MODE_OPEN);       /* Fri 23:00 still open */
    EXPECT_MODE(s, mk(2026,4,24, 23,59), SCH_MODE_OPEN);
    EXPECT_MODE(s, mk(2026,4,25, 0,0),   SCH_MODE_CLOSED);     /* Sat 00:00 closes */
    EXPECT_MODE(s, mk(2026,4,25, 6,59),  SCH_MODE_CLOSED);
    EXPECT_MODE(s, mk(2026,4,25, 7,0),   SCH_MODE_FILTERED);   /* Sat 07:00 */
    EXPECT_MODE(s, mk(2026,4,25, 8,59),  SCH_MODE_FILTERED);   /* still filtered */
    EXPECT_MODE(s, mk(2026,4,25, 9,0),   SCH_MODE_OPEN);       /* Sat 09:00 weekend open */

    /* Saturday night → Sunday: Sat has no bedtime, Sun 00:00 closes. */
    EXPECT_MODE(s, mk(2026,4,25, 23,0),  SCH_MODE_OPEN);       /* Sat 23:00 open */
    EXPECT_MODE(s, mk(2026,4,26, 0,0),   SCH_MODE_CLOSED);     /* Sun 00:00 */
    EXPECT_MODE(s, mk(2026,4,26, 7,0),   SCH_MODE_FILTERED);
    EXPECT_MODE(s, mk(2026,4,26, 9,0),   SCH_MODE_OPEN);       /* Sun 09:00 weekend open */
    EXPECT_MODE(s, mk(2026,4,26, 23,0),  SCH_MODE_CLOSED);     /* Sun 23:00 bedtime */

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

    schedule_free(s);
    printf("OK test_schedule\n");
    return 0;
}
