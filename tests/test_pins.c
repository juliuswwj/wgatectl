#include "pins.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static char path_buf[256];

static const char *tmp_path(void) {
    snprintf(path_buf, sizeof(path_buf),
             "/tmp/wgatectl_test_pins.%d.json", (int)getpid());
    unlink(path_buf);
    return path_buf;
}

int main(void) {
    /* `ipset_bin` empty so pins_dump_to_ipsets does not actually fork ipset. */
    const char *path = tmp_path();
    wg_pins_t *p = pins_new(path, "");
    assert(p);
    assert(pins_load(p) == 0);

    wg_leases_t leases;
    memset(&leases, 0, sizeof(leases));

    int64_t now    = (int64_t)time(NULL);
    int64_t future = now + 3600;
    int64_t past   = now - 60;

    /* Set / update / remove. */
    assert(pins_set(p, &leases, "10.6.6.99", SCH_MODE_OPEN, future, "homework") == 1);
    bool pinned = false;
    assert(pins_for_ip(p, &leases, 0x0A060663, now, &pinned) == SCH_MODE_OPEN);
    assert(pinned == true);
    assert(pins_for_ip(p, &leases, 0x0A060664, now, &pinned) == SCH_MODE_OPEN);
    assert(pinned == false);

    /* Update in place: same key → new mode/expiry, total still 1. */
    assert(pins_set(p, &leases, "10.6.6.99", SCH_MODE_FILTERED, future, NULL) == 1);
    assert(pins_for_ip(p, &leases, 0x0A060663, now, &pinned) == SCH_MODE_FILTERED);
    assert(pins_count(p, now) == 1);

    /* Add a closed pin for another IP. */
    assert(pins_set(p, &leases, "10.6.6.100", SCH_MODE_CLOSED, future, "discipline") == 1);
    assert(pins_count(p, now) == 2);

    /* Expired pins are filtered out by pins_for_ip / pins_count. */
    assert(pins_set(p, &leases, "10.6.6.101", SCH_MODE_OPEN, past, "stale") == 1);
    /* Note: pins_set itself does not validate until_wall — caller (HTTP
     * handler) does. But pins_for_ip respects until. */
    assert(pins_for_ip(p, &leases, 0x0A060665, now, &pinned) == SCH_MODE_OPEN);
    assert(pinned == false);  /* expired */
    /* pins_tick should drop the expired one. */
    pins_tick(p, now);
    assert(pins_count(p, now) == 2);

    /* Remove. */
    assert(pins_remove(p, &leases, "10.6.6.99") == 1);
    assert(pins_remove(p, &leases, "10.6.6.99") == 0);
    assert(pins_for_ip(p, &leases, 0x0A060663, now, &pinned) == SCH_MODE_OPEN);
    assert(pinned == false);

    /* Persistence: reload from disk. */
    pins_free(p);
    p = pins_new(path, "");
    assert(p);
    assert(pins_load(p) == 0);
    assert(pins_count(p, now) == 1);
    assert(pins_for_ip(p, &leases, 0x0A060664, now, &pinned) == SCH_MODE_CLOSED);
    assert(pinned == true);
    pins_free(p);

    unlink(path);
    printf("OK test_pins\n");
    return 0;
}
