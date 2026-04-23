#include "supervisor.h"
#include "leases.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main(void) {
    wg_supervisor_t *s = supervisor_new(NULL, NULL);
    assert(s);

    /* Add target "example.com" */
    assert(supervisor_add_target(s, "example.com") == 1);
    assert(supervisor_add_target(s, "example.com") == 0);   /* already */
    assert(supervisor_add_target(s, "epicgames.com") == 1);

    /* Suffix match, case-insensitive, label-boundary. */
    assert(supervisor_domain_matches(s, "example.com")       == true);
    assert(supervisor_domain_matches(s, "Example.com")       == true);
    assert(supervisor_domain_matches(s, "login.example.com") == true);
    assert(supervisor_domain_matches(s, "a.b.example.com")   == true);
    assert(supervisor_domain_matches(s, "example.co")        == false);
    assert(supervisor_domain_matches(s, "abcexample.com")    == false);
    assert(supervisor_domain_matches(s, "")                  == false);
    assert(supervisor_domain_matches(s, "other.com")         == false);
    assert(supervisor_domain_matches(s, "epicgames.com")     == true);

    /* Detection state machine: no lease table needed since we only test IP
     * keys (supervisor_triggered_ips resolves through leases but we query
     * by IP directly, and triggers are keyed canonically — for raw IPs the
     * canonical form is dotted-quad). */
    wg_leases_t leases;
    memset(&leases, 0, sizeof(leases));

    const uint32_t ip_a = 0x0A060605;   /* 10.6.6.5 */
    const uint32_t ip_b = 0x0A060606;   /* 10.6.6.6 */

    int64_t t = 1745000000;
    /* 4 matching minutes, then a miss: counter resets, no trigger. */
    for (int i = 0; i < 4; i++) {
        supervisor_observe(s, ip_a, "login.example.com");
        supervisor_commit_minute(s, &leases, NULL, t);
        t += 60;
    }
    /* Miss this minute: counter should reset. */
    supervisor_commit_minute(s, &leases, NULL, t);
    t += 60;
    assert(supervisor_ip_triggered(s, &leases, ip_a, t) == false);

    /* 5 consecutive matches: trigger fires at minute 5. */
    for (int i = 0; i < 4; i++) {
        supervisor_observe(s, ip_a, "example.com");
        supervisor_commit_minute(s, &leases, NULL, t);
        t += 60;
    }
    assert(supervisor_ip_triggered(s, &leases, ip_a, t) == false);  /* not yet */
    supervisor_observe(s, ip_a, "example.com");
    supervisor_commit_minute(s, &leases, NULL, t);
    assert(supervisor_ip_triggered(s, &leases, ip_a, t) == true);   /* fired */
    /* ip_b hasn't done anything. */
    assert(supervisor_ip_triggered(s, &leases, ip_b, t) == false);

    /* supervisor_triggered_ips returns ip_a. */
    uint32_t trig[8];
    size_t n = supervisor_triggered_ips(s, &leases, t, trig, 8);
    assert(n == 1);
    assert(trig[0] == ip_a);

    /* Advance one hour; trigger should expire on tick. */
    int64_t t_after = t + 3600 + 1;
    supervisor_tick(s, &leases, t_after);
    assert(supervisor_ip_triggered(s, &leases, ip_a, t_after) == false);

    /* After expiry, counter is reset: need another 5 consecutive matches. */
    int64_t t2 = t_after + 60;
    for (int i = 0; i < 4; i++) {
        supervisor_observe(s, ip_a, "example.com");
        supervisor_commit_minute(s, &leases, NULL, t2);
        t2 += 60;
    }
    assert(supervisor_ip_triggered(s, &leases, ip_a, t2) == false);
    supervisor_observe(s, ip_a, "example.com");
    supervisor_commit_minute(s, &leases, NULL, t2);
    assert(supervisor_ip_triggered(s, &leases, ip_a, t2) == true);

    /* Target removal. */
    assert(supervisor_remove_target(s, "example.com")       == 1);
    assert(supervisor_domain_matches(s, "login.example.com") == false);
    assert(supervisor_domain_matches(s, "epicgames.com")     == true);

    supervisor_free(s);
    printf("OK test_supervisor\n");
    return 0;
}
