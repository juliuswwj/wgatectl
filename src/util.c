#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

bool ip_parse(const char *s, uint32_t *out) {
    if (!s || !out) return false;
    unsigned a, b, c, d;
    char tail;
    if (sscanf(s, "%u.%u.%u.%u%c", &a, &b, &c, &d, &tail) != 4) return false;
    if (a > 255 || b > 255 || c > 255 || d > 255) return false;
    *out = (a << 24) | (b << 16) | (c << 8) | d;
    return true;
}

bool cidr_parse(const char *s, uint32_t *addr, uint32_t *mask) {
    if (!s || !addr || !mask) return false;
    char copy[32];
    size_t n = strlen(s);
    if (n >= sizeof(copy)) return false;
    memcpy(copy, s, n + 1);
    char *slash = strchr(copy, '/');
    unsigned bits = 32;
    if (slash) {
        *slash = 0;
        char tail;
        if (sscanf(slash + 1, "%u%c", &bits, &tail) != 1) return false;
        if (bits > 32) return false;
    }
    uint32_t ip;
    if (!ip_parse(copy, &ip)) return false;
    uint32_t m = bits == 0 ? 0 : (0xFFFFFFFFu << (32 - bits));
    *mask = m;
    *addr = ip & m;
    return true;
}

void ip_format(uint32_t ip, char *buf) {
    snprintf(buf, 16, "%u.%u.%u.%u",
             (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
             (ip >>  8) & 0xFF,  ip        & 0xFF);
}

bool ip_in_subnet(uint32_t ip, uint32_t addr, uint32_t mask) {
    return (ip & mask) == (addr & mask);
}

bool mac_parse(const char *s, uint8_t out[6]) {
    if (!s) return false;
    unsigned v[6];
    char tail;
    int n = sscanf(s, "%x:%x:%x:%x:%x:%x%c",
                   &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &tail);
    if (n != 6) return false;
    for (int i = 0; i < 6; i++) {
        if (v[i] > 0xFF) return false;
        out[i] = (uint8_t)v[i];
    }
    return true;
}

void mac_format(const uint8_t mac[6], char *buf) {
    snprintf(buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

uint64_t now_mono_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

int64_t now_wall_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec;
}

static void fmt_iso8601(const struct tm *tm, long gmtoff, char *buf, size_t cap) {
    int sign = gmtoff >= 0 ? 1 : -1;
    long off = gmtoff * sign;
    int oh = (int)(off / 3600);
    int om = (int)((off % 3600) / 60);
    snprintf(buf, cap, "%04d-%02d-%02dT%02d:%02d:%02d%c%02d:%02d",
             tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
             tm->tm_hour, tm->tm_min, tm->tm_sec,
             sign >= 0 ? '+' : '-', oh, om);
}

void now_wall_iso8601(char *buf, size_t cap) {
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    fmt_iso8601(&tm, tm.tm_gmtoff, buf, cap);
}

void ts_iso8601(int64_t secs, char *buf, size_t cap) {
    time_t t = (time_t)secs;
    struct tm tm;
    localtime_r(&t, &tm);
    fmt_iso8601(&tm, tm.tm_gmtoff, buf, cap);
}

void now_ymd(char *buf, size_t cap) {
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    snprintf(buf, cap, "%04d%02d%02d",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
}

void now_hm_wday(int *hm, int *wday) {
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    if (hm)   *hm   = tm.tm_hour * 100 + tm.tm_min;
    if (wday) *wday = tm.tm_wday;
}

char *read_small_file(const char *path, size_t limit, size_t *out_len) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;
    char *buf = malloc(limit + 1);
    if (!buf) { close(fd); return NULL; }
    size_t total = 0;
    while (total < limit) {
        ssize_t r = read(fd, buf + total, limit - total);
        if (r < 0) {
            if (errno == EINTR) continue;
            free(buf); close(fd); return NULL;
        }
        if (r == 0) break;
        total += (size_t)r;
    }
    close(fd);
    buf[total] = 0;
    if (out_len) *out_len = total;
    return buf;
}

int atomic_write(const char *path, const void *data, size_t len) {
    char tmp[512];
    int n = snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, (int)getpid());
    if (n <= 0 || (size_t)n >= sizeof(tmp)) return -1;

    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) return -1;
    const char *p = data;
    size_t left = len;
    while (left) {
        ssize_t w = write(fd, p, left);
        if (w < 0) {
            if (errno == EINTR) continue;
            close(fd); unlink(tmp); return -1;
        }
        p += w; left -= (size_t)w;
    }
    if (fsync(fd) < 0) { close(fd); unlink(tmp); return -1; }
    if (close(fd) < 0) { unlink(tmp); return -1; }
    if (rename(tmp, path) < 0) { unlink(tmp); return -1; }
    return 0;
}

char *xstrdup(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char *r = malloc(n);
    if (!r) return NULL;
    memcpy(r, s, n);
    return r;
}

int mkdir_p(const char *path, int mode) {
    if (!path || !*path) return -1;
    char buf[512];
    size_t n = strlen(path);
    if (n >= sizeof(buf)) return -1;
    memcpy(buf, path, n + 1);

    for (size_t i = 1; i < n; i++) {
        if (buf[i] == '/') {
            buf[i] = 0;
            if (mkdir(buf, mode) < 0 && errno != EEXIST) return -1;
            buf[i] = '/';
        }
    }
    if (mkdir(buf, mode) < 0 && errno != EEXIST) return -1;
    return 0;
}

bool resolve_bin(const char *hint, const char *name, char *out, size_t cap) {
    if (hint && hint[0] == '/' && access(hint, X_OK) == 0) {
        size_t n = strlen(hint);
        if (n >= cap) return false;
        memcpy(out, hint, n + 1);
        return true;
    }
    static const char *const dirs[] = {
        "/usr/sbin", "/sbin", "/usr/local/sbin",
        "/usr/bin",  "/bin",  "/usr/local/bin",
        NULL
    };
    for (int i = 0; dirs[i]; i++) {
        char path[256];
        int n = snprintf(path, sizeof(path), "%s/%s", dirs[i], name);
        if (n <= 0 || (size_t)n >= sizeof(path)) continue;
        if (access(path, X_OK) == 0) {
            if ((size_t)n >= cap) return false;
            memcpy(out, path, (size_t)n + 1);
            return true;
        }
    }
    return false;
}
