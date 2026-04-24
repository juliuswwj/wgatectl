#include "blocks.h"
#include "leases.h"
#include "util.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Write `content` to path; assert success. */
static void write_file(const char *path, const char *content) {
    int rc = atomic_write(path, content, strlen(content));
    assert(rc == 0);
}

/* Slurp whole file; caller frees. */
static char *slurp(const char *path) {
    size_t n = 0;
    return read_small_file(path, 1 << 20, &n);
}

int main(void) {
    wg_leases_t leases;
    memset(&leases, 0, sizeof(leases));

    char path[] = "/tmp/wgatectl_test_blocks.XXXXXX.json";
    /* mkstemps would be ideal, but we just compose a unique name */
    snprintf(path, sizeof(path), "/tmp/wgatectl_test_blocks.%d.json",
             (int)getpid());

    /* ---- add + reason + clear ---- */
    {
        wg_blocks_t b;
        blocks_init(&b, path);

        assert(blocks_add(&b, &leases, "10.6.6.9", "homework", 1700000000) == 1);
        assert(blocks_add(&b, &leases, "10.6.6.9", NULL, 0)                == 0); /* dup */
        assert(blocks_add(&b, &leases, "10.6.6.10", NULL, 0)               == 1);

        assert(blocks_contains(&b, &leases, "10.6.6.9"));
        assert(!blocks_contains(&b, &leases, "10.6.6.11"));

        const char *r = blocks_reason(&b, &leases, "10.6.6.9");
        assert(r != NULL && strcmp(r, "homework") == 0);
        assert(blocks_reason(&b, &leases, "10.6.6.10") == NULL);

        assert(b.n == 2);
        blocks_clear(&b);
        assert(b.n == 0);
        assert(!blocks_contains(&b, &leases, "10.6.6.9"));

        blocks_free(&b);
    }

    /* ---- save writes object array with reason/added_at ---- */
    {
        wg_blocks_t b;
        blocks_init(&b, path);
        blocks_add(&b, &leases, "10.6.6.9", "homework", 1700000000);
        blocks_add(&b, &leases, "10.6.6.10", NULL, 0);
        assert(blocks_save(&b) == 0);

        char *disk = slurp(path);
        assert(disk != NULL);
        assert(strstr(disk, "\"key\"") != NULL);
        assert(strstr(disk, "\"reason\":\"homework\"") != NULL);
        assert(strstr(disk, "\"added_at\":1700000000") != NULL);
        /* entry without reason/added_at: key only */
        assert(strstr(disk, "\"10.6.6.10\"") != NULL);
        free(disk);
        blocks_free(&b);
    }

    /* ---- load reads the object array back ---- */
    {
        wg_blocks_t b;
        blocks_init(&b, path);
        assert(blocks_load(&b) == 0);
        assert(b.n == 2);
        assert(blocks_contains(&b, &leases, "10.6.6.9"));
        const char *r = blocks_reason(&b, &leases, "10.6.6.9");
        assert(r != NULL && strcmp(r, "homework") == 0);
        blocks_free(&b);
    }

    /* ---- load tolerates legacy array-of-strings format ---- */
    {
        write_file(path, "[\"10.6.6.5\", \"laptop\"]");
        wg_blocks_t b;
        blocks_init(&b, path);
        assert(blocks_load(&b) == 0);
        assert(b.n == 2);
        assert(blocks_contains(&b, &leases, "10.6.6.5"));
        assert(blocks_reason(&b, &leases, "10.6.6.5") == NULL);  /* no reason in legacy */
        blocks_free(&b);
    }

    /* ---- remove ---- */
    {
        wg_blocks_t b;
        blocks_init(&b, NULL);
        blocks_add(&b, &leases, "10.6.6.9", "x", 1);
        blocks_add(&b, &leases, "10.6.6.10", "y", 2);
        blocks_add(&b, &leases, "10.6.6.11", "z", 3);
        assert(blocks_remove(&b, &leases, "10.6.6.10") == 1);
        assert(blocks_remove(&b, &leases, "10.6.6.10") == 0);
        assert(b.n == 2);
        assert(blocks_contains(&b, &leases, "10.6.6.9"));
        assert(blocks_contains(&b, &leases, "10.6.6.11"));
        assert(!blocks_contains(&b, &leases, "10.6.6.10"));
        /* reasons for remaining entries survive the shuffle */
        assert(strcmp(blocks_reason(&b, &leases, "10.6.6.9"), "x") == 0);
        assert(strcmp(blocks_reason(&b, &leases, "10.6.6.11"), "z") == 0);
        blocks_free(&b);
    }

    unlink(path);
    printf("OK test_blocks\n");
    return 0;
}
