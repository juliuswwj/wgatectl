#include "filterd.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Each call returns a path in its own static buffer slot, so callers can
 * keep multiple distinct paths alive simultaneously. */
static const char *tmp_path(const char *suffix) {
    static char buf[4][256];
    static int  next = 0;
    char *out = buf[next++ & 3];
    snprintf(out, 256, "/tmp/wgatectl_test_filterd.%d.%s.json",
             (int)getpid(), suffix);
    unlink(out);
    return out;
}

int main(void) {
    /* `ipset_bin` empty so observe/flush does not actually fork ipset
     * (we're not running as root in CI). */
    const char *path = tmp_path("primary");
    wg_filterd_t *f = filterd_new(path, "", NULL);
    assert(f);
    assert(filterd_load(f) == 0);

    /* Add some targets */
    assert(filterd_add_target(f, "example.com") == 1);
    assert(filterd_add_target(f, "Example.com") == 0);   /* dup, case-insensitive */
    assert(filterd_add_target(f, "ads.tracker.io") == 1);

    /* Label-boundary suffix match. */
    assert(filterd_domain_matches(f, "example.com")        == true);
    assert(filterd_domain_matches(f, "www.example.com")    == true);
    assert(filterd_domain_matches(f, "deep.cdn.example.com") == true);
    assert(filterd_domain_matches(f, "abcexample.com")     == false);
    assert(filterd_domain_matches(f, "example.com.evil")   == false);
    assert(filterd_domain_matches(f, "")                   == false);
    assert(filterd_domain_matches(f, NULL)                 == false);

    /* Observe a few IPs (no kernel side effects when ipset_bin == ""). */
    filterd_observe_ip(f, 0x0A060664);   /* 10.6.6.100 */
    filterd_observe_ip(f, 0x0A060664);   /* dup, should dedupe in lookback */
    filterd_observe_ip(f, 0x0A060665);
    filterd_flush(f, 0);                  /* drains the pending queue */

    /* Remove */
    assert(filterd_remove_target(f, "example.com") == 1);
    assert(filterd_remove_target(f, "example.com") == 0);   /* already gone */
    assert(filterd_domain_matches(f, "www.example.com") == false);
    assert(filterd_domain_matches(f, "ads.tracker.io")  == true);

    /* Persistence: save was called inside add/remove. Reload from disk. */
    filterd_free(f);
    f = filterd_new(path, "", NULL);
    assert(f);
    assert(filterd_load(f) == 0);
    assert(filterd_domain_matches(f, "ads.tracker.io")  == true);
    assert(filterd_domain_matches(f, "example.com")     == false);
    filterd_free(f);

    /* Legacy migration: when filterd.json is absent but supervised.json
     * exists, the legacy file is loaded once. */
    const char *legacy = tmp_path("legacy");
    {
        FILE *fp = fopen(legacy, "w");
        assert(fp);
        fputs("[\"legacy.example\",\"foo.test\"]\n", fp);
        fclose(fp);
    }
    const char *fresh = tmp_path("fresh");
    f = filterd_new(fresh, "", legacy);
    assert(f);
    assert(filterd_load(f) == 0);
    assert(filterd_domain_matches(f, "legacy.example") == true);
    assert(filterd_domain_matches(f, "foo.test")       == true);
    filterd_free(f);

    unlink(path);
    unlink(legacy);
    unlink(fresh);

    printf("OK test_filterd\n");
    return 0;
}
