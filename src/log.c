#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int g_debug = 0;

void logger_init(int debug) {
    const char *env = getenv("WG_DEBUG");
    if (debug || (env && *env && strcmp(env, "0") != 0)) g_debug = 1;
}

static const char *lvl_str(log_level_t l) {
    switch (l) {
        case LOG_DEBUG: return "DBG";
        case LOG_INFO:  return "INF";
        case LOG_WARN:  return "WRN";
        case LOG_ERR:   return "ERR";
    }
    return "???";
}

void log_msg(log_level_t lvl, const char *fmt, ...) {
    if (lvl == LOG_DEBUG && !g_debug) return;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);
    char tbuf[32];
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &tm);

    fprintf(stderr, "%s.%03ld %s ", tbuf, ts.tv_nsec / 1000000L, lvl_str(lvl));
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}
