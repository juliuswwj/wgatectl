#include "dnsmasq_conf.h"
#include "util.h"

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void write_file(const char *path, const char *content) {
    int rc = atomic_write(path, content, strlen(content));
    assert(rc == 0);
}

static char *slurp(const char *path) {
    size_t n = 0;
    return read_small_file(path, 1 << 20, &n);
}

int main(void) {
    /* name validation */
    assert(dnsmasq_name_is_valid("alice"));
    assert(dnsmasq_name_is_valid("alice-phone"));
    assert(dnsmasq_name_is_valid("a1.b2_c3-d4"));
    assert(!dnsmasq_name_is_valid(""));
    assert(!dnsmasq_name_is_valid("-alice"));   /* leading hyphen */
    assert(!dnsmasq_name_is_valid(".alice"));   /* leading dot */
    assert(!dnsmasq_name_is_valid("alice phone"));
    assert(!dnsmasq_name_is_valid("alice,phone"));
    assert(!dnsmasq_name_is_valid("a=b"));

    char path[64];
    snprintf(path, sizeof(path), "/tmp/wgatectl_test_dnsmasq.%d.conf",
             (int)getpid());

    uint8_t mac_a[6] = { 0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33 };
    uint8_t mac_c[6] = { 0xaa, 0xbb, 0xcc, 0x77, 0x88, 0x99 };
    uint32_t ip_a, ip_c;
    ip_parse("10.6.6.10", &ip_a);
    ip_parse("10.6.6.12", &ip_c);

    /* ---- insert into empty file (append order is NAME,IP,MAC) ---- */
    write_file(path, "# header\n");
    bool changed = false;
    assert(dnsmasq_set_host_name(path, mac_a, ip_a, "alice", &changed)
           == DNS_NAME_OK);
    assert(changed);
    {
        char *s = slurp(path);
        assert(strstr(s, "dhcp-host=alice,10.6.6.10,aa:bb:cc:11:22:33"));
        free(s);
    }

    /* ---- idempotent re-set ---- */
    changed = true;
    assert(dnsmasq_set_host_name(path, mac_a, ip_a, "alice", &changed)
           == DNS_NAME_OK);
    assert(!changed);

    /* ---- rename existing entry, preserving other fields ---- */
    write_file(path,
        "dhcp-range=10.6.6.50,10.6.6.200,12h\n"
        "dhcp-host=aa:bb:cc:11:22:33,10.6.6.10,alice,24h\n"
        "dhcp-host=aa:bb:cc:44:55:66,10.6.6.11,bob\n");
    changed = false;
    assert(dnsmasq_set_host_name(path, mac_a, ip_a, "alice2", &changed)
           == DNS_NAME_OK);
    assert(changed);
    {
        char *s = slurp(path);
        /* lease time must be preserved on the updated line */
        assert(strstr(s, "dhcp-host=aa:bb:cc:11:22:33,10.6.6.10,alice2,24h"));
        /* other entries untouched */
        assert(strstr(s, "dhcp-host=aa:bb:cc:44:55:66,10.6.6.11,bob"));
        assert(strstr(s, "dhcp-range=10.6.6.50,10.6.6.200,12h"));
        free(s);
    }

    /* ---- duplicate name on a different MAC is rejected ---- */
    changed = true;
    assert(dnsmasq_set_host_name(path, mac_c, ip_c, "bob", &changed)
           == DNS_NAME_DUPLICATE);
    /* file must be unchanged after duplicate rejection */
    {
        char *s = slurp(path);
        assert(!strstr(s, "aa:bb:cc:77:88:99"));
        free(s);
    }

    /* ---- insert new host when MAC doesn't exist ---- */
    changed = false;
    assert(dnsmasq_set_host_name(path, mac_c, ip_c, "carol", &changed)
           == DNS_NAME_OK);
    assert(changed);
    {
        char *s = slurp(path);
        assert(strstr(s, "dhcp-host=carol,10.6.6.12,aa:bb:cc:77:88:99"));
        free(s);
    }

    /* ---- zero MAC is rejected ---- */
    uint8_t mac_zero[6] = {0};
    assert(dnsmasq_set_host_name(path, mac_zero, ip_a, "x", &changed)
           == DNS_NAME_NO_MAC);

    /* ---- bad name is rejected ---- */
    assert(dnsmasq_set_host_name(path, mac_a, ip_a, "bad,name", &changed)
           == DNS_NAME_INVALID);

    /* ---- preserves MAC casing / indent / unrelated content ---- */
    {
        const char *orig =
            "# top comment\n"
            "domain-needed\n"
            "bogus-priv\n"
            "dhcp-range=10.6.6.50,10.6.6.200,12h\n"
            "dhcp-option=option:router,10.6.6.1\n"
            "  dhcp-host=AA:BB:CC:11:22:33,10.6.6.10,alice,24h\n"
            "dhcp-host=aa:bb:cc:44:55:66,10.6.6.11,bob\n"
            "address=/ads.example/0.0.0.0\n";
        write_file(path, orig);
        changed = false;
        assert(dnsmasq_set_host_name(path, mac_a, ip_a, "alice3", &changed)
               == DNS_NAME_OK);
        assert(changed);
        char *s = slurp(path);
        /* Only the name token changed; MAC stays uppercase, 2-space
         * indent stays, lease time stays, IP stays. */
        assert(strstr(s, "  dhcp-host=AA:BB:CC:11:22:33,10.6.6.10,alice3,24h\n"));
        /* bob's entry, dhcp-range, dhcp-option, domain-needed, comment,
         * address= line all untouched. */
        assert(strstr(s, "# top comment\n"));
        assert(strstr(s, "domain-needed\n"));
        assert(strstr(s, "bogus-priv\n"));
        assert(strstr(s, "dhcp-range=10.6.6.50,10.6.6.200,12h\n"));
        assert(strstr(s, "dhcp-option=option:router,10.6.6.1\n"));
        assert(strstr(s, "dhcp-host=aa:bb:cc:44:55:66,10.6.6.11,bob\n"));
        assert(strstr(s, "address=/ads.example/0.0.0.0\n"));
        free(s);
    }

    /* ---- handles set:/tag: extension fields without eating them ---- */
    {
        const char *orig =
            "dhcp-host=set:trusted,aa:bb:cc:11:22:33,10.6.6.10,alice,24h\n"
            "dhcp-host=id:my-id,tag:foo,aa:bb:cc:44:55:66,10.6.6.11,bob\n";
        write_file(path, orig);
        changed = false;
        assert(dnsmasq_set_host_name(path, mac_a, ip_a, "alice2", &changed)
               == DNS_NAME_OK);
        assert(changed);
        char *s = slurp(path);
        /* set:trusted stays first, MAC/IP unchanged, name replaced,
         * lease time preserved */
        assert(strstr(s,
            "dhcp-host=set:trusted,aa:bb:cc:11:22:33,10.6.6.10,alice2,24h\n"));
        /* bob's line completely untouched */
        assert(strstr(s,
            "dhcp-host=id:my-id,tag:foo,aa:bb:cc:44:55:66,10.6.6.11,bob\n"));
        free(s);
    }

    /* ---- inserts name when line had none ---- */
    {
        const char *orig = "dhcp-host=aa:bb:cc:11:22:33,10.6.6.10,24h\n";
        write_file(path, orig);
        changed = false;
        assert(dnsmasq_set_host_name(path, mac_a, ip_a, "alice", &changed)
               == DNS_NAME_OK);
        assert(changed);
        char *s = slurp(path);
        /* name inserted after IP; lease time preserved */
        assert(strstr(s,
            "dhcp-host=aa:bb:cc:11:22:33,10.6.6.10,alice,24h\n"));
        free(s);
    }

    /* ---- handles NAME,IP,MAC field order (common in hand-written confs) ---- */
    {
        uint8_t mac_printer[6] = { 0xe0, 0xce, 0xc3, 0xb6, 0xd0, 0x6c };
        uint8_t mac_other[6]   = { 0xe0, 0xce, 0xc3, 0xb6, 0xd0, 0x99 };
        uint32_t ip_printer;
        ip_parse("10.6.6.51", &ip_printer);

        const char *orig =
            "# printers\n"
            "dhcp-host=printer_dell,10.6.6.51,e0:ce:c3:b6:d0:6c\n"
            "dhcp-host=server,10.6.6.52,e0:ce:c3:b6:d0:99\n";
        write_file(path, orig);

        /* rename in NAME,IP,MAC order — only the name slot changes,
         * IP and MAC keep their positions and casing */
        changed = false;
        assert(dnsmasq_set_host_name(path, mac_printer, ip_printer,
                                     "printer_hp", &changed) == DNS_NAME_OK);
        assert(changed);
        {
            char *s = slurp(path);
            assert(strstr(s,
                "dhcp-host=printer_hp,10.6.6.51,e0:ce:c3:b6:d0:6c\n"));
            /* other line and comment untouched */
            assert(strstr(s, "# printers\n"));
            assert(strstr(s,
                "dhcp-host=server,10.6.6.52,e0:ce:c3:b6:d0:99\n"));
            free(s);
        }

        /* uniqueness check works across layouts too */
        assert(dnsmasq_set_host_name(path, mac_other, 0,
                                     "printer_hp", &changed)
               == DNS_NAME_DUPLICATE);

        /* idempotent in this layout as well */
        changed = true;
        assert(dnsmasq_set_host_name(path, mac_printer, ip_printer,
                                     "printer_hp", &changed) == DNS_NAME_OK);
        assert(!changed);
    }

    /* ---- idempotent on already-matching line, even weird formatting ---- */
    {
        const char *orig =
            "dhcp-host=AA:BB:CC:11:22:33,10.6.6.10,alice,infinite\n";
        write_file(path, orig);
        changed = true;
        assert(dnsmasq_set_host_name(path, mac_a, ip_a, "alice", &changed)
               == DNS_NAME_OK);
        assert(!changed);
        char *s = slurp(path);
        assert(strcmp(s, orig) == 0);   /* byte-for-byte identical */
        free(s);
    }

    unlink(path);
    printf("OK test_dnsmasq_conf\n");
    return 0;
}
