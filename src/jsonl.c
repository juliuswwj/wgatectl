#include "jsonl.h"
#include "log.h"
#include "util.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

struct jsonl {
    char dir[256];
    char current_ymd[16];  /* YYYYMMDD of the open fd */
    int  fd;               /* -1 if not open */
    int  retain_days;
};

static int ensure_dir(const char *dir) {
    struct stat st;
    if (stat(dir, &st) == 0 && S_ISDIR(st.st_mode)) return 0;
    if (mkdir_p(dir, 0755) == 0) return 0;
    LOG_E("mkdir_p(%s): %s", dir, strerror(errno));
    return -1;
}

static void path_for(const char *dir, const char *ymd, char *out, size_t cap) {
    snprintf(out, cap, "%s/events-%s.jsonl", dir, ymd);
}

static void prune(jsonl_t *j) {
    if (j->retain_days <= 0) return;
    DIR *d = opendir(j->dir);
    if (!d) return;
    time_t now = time(NULL);
    time_t cutoff = now - (time_t)j->retain_days * 86400;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strncmp(de->d_name, "events-", 7) != 0) continue;
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", j->dir, de->d_name);
        struct stat st;
        if (stat(path, &st) != 0) continue;
        if (st.st_mtime < cutoff) {
            if (unlink(path) == 0) LOG_I("jsonl: pruned %s", de->d_name);
        }
    }
    closedir(d);
}

static int open_for(jsonl_t *j, const char *ymd) {
    char path[320];
    path_for(j->dir, ymd, path, sizeof(path));
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (fd < 0) {
        LOG_E("jsonl: open %s: %s", path, strerror(errno));
        return -1;
    }
    if (j->fd >= 0) close(j->fd);
    j->fd = fd;
    strncpy(j->current_ymd, ymd, sizeof(j->current_ymd) - 1);
    j->current_ymd[sizeof(j->current_ymd) - 1] = 0;
    return 0;
}

static int ensure_today(jsonl_t *j) {
    char ymd[16];
    now_ymd(ymd, sizeof(ymd));
    if (j->fd < 0 || strcmp(ymd, j->current_ymd) != 0) {
        if (j->fd >= 0) {
            fsync(j->fd);
            close(j->fd);
            j->fd = -1;
        }
        if (open_for(j, ymd) < 0) return -1;
        prune(j);
    }
    return 0;
}

jsonl_t *jsonl_open(const char *dir, int retain_days) {
    jsonl_t *j = calloc(1, sizeof(*j));
    if (!j) return NULL;
    strncpy(j->dir, dir, sizeof(j->dir) - 1);
    j->dir[sizeof(j->dir) - 1] = 0;
    j->retain_days = retain_days;
    j->fd = -1;
    ensure_dir(j->dir);
    if (ensure_today(j) < 0) { free(j); return NULL; }
    LOG_I("jsonl: writing to %s/events-%s.jsonl", j->dir, j->current_ymd);
    return j;
}

int jsonl_append(jsonl_t *j, const char *buf, size_t len) {
    if (!j) return -1;
    if (ensure_today(j) < 0) return -1;
    /* Copy line + \n into one buffer so the O_APPEND write is a single call.
     * Use the stack when small, else heap-alloc briefly. */
    char stack[4096];
    char *p;
    size_t plen = len + 1;
    int heap = 0;
    if (plen <= sizeof(stack)) {
        p = stack;
    } else {
        p = malloc(plen);
        if (!p) return -1;
        heap = 1;
    }
    memcpy(p, buf, len);
    p[len] = '\n';

    size_t written = 0;
    while (written < plen) {
        ssize_t w = write(j->fd, p + written, plen - written);
        if (w < 0) {
            if (errno == EINTR) continue;
            LOG_W("jsonl: write failed: %s", strerror(errno));
            if (heap) free(p);
            return -1;
        }
        written += (size_t)w;
    }
    if (heap) free(p);
    return 0;
}

int jsonl_sync(jsonl_t *j) {
    if (!j || j->fd < 0) return 0;
    if (fdatasync(j->fd) < 0) {
        LOG_W("jsonl: fdatasync: %s", strerror(errno));
        return -1;
    }
    return 0;
}

/* Extract the first unix-seconds value from a line that starts with
 *   {"ts":"YYYY-MM-DDTHH:MM:SS±HH:MM",...
 * Returns 0 if it can't be parsed. */
static long line_ts(const char *line, size_t len) {
    const char *p = memchr(line, '"', len);
    if (!p) return 0;
    /* find ":" after the "ts" key */
    const char *q = memchr(p + 1, ':', len - (size_t)(p + 1 - line));
    if (!q) return 0;
    q++;
    while (q < line + len && (*q == ' ' || *q == '"')) q++;
    if (q >= line + len) return 0;
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    int y, mo, d, h, mi, s, oh = 0, om = 0;
    char sgn = '+';
    int n = sscanf(q, "%d-%d-%dT%d:%d:%d%c%d:%d",
                   &y, &mo, &d, &h, &mi, &s, &sgn, &oh, &om);
    if (n < 6) return 0;
    tm.tm_year = y - 1900;
    tm.tm_mon  = mo - 1;
    tm.tm_mday = d;
    tm.tm_hour = h;
    tm.tm_min  = mi;
    tm.tm_sec  = s;
    time_t t = timegm(&tm);
    if (n >= 9) {
        long off = oh * 3600L + om * 60L;
        if (sgn == '-') off = -off;
        t -= off;
    }
    return (long)t;
}

int jsonl_tail(jsonl_t *j, long since_ts,
               int (*cb)(void *ctx, const char *line, size_t len),
               void *ctx) {
    if (!j || j->fd < 0) return 0;
    if (fdatasync(j->fd) < 0) { /* ignore */ }
    char path[320];
    path_for(j->dir, j->current_ymd, path, sizeof(path));
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while ((n = getline(&line, &cap, f)) != -1) {
        size_t len = (size_t)n;
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            len--;
        if (since_ts > 0) {
            long t = line_ts(line, len);
            if (t <= since_ts) continue;
        }
        if (cb(ctx, line, len) != 0) { rc = -1; break; }
    }
    free(line);
    fclose(f);
    return rc;
}

void jsonl_close(jsonl_t *j) {
    if (!j) return;
    if (j->fd >= 0) { fsync(j->fd); close(j->fd); j->fd = -1; }
    free(j);
}
