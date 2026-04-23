#ifndef WGATECTL_LOG_H
#define WGATECTL_LOG_H

#include <stdarg.h>

typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO  = 1,
    LOG_WARN  = 2,
    LOG_ERR   = 3
} log_level_t;

/* Initialise the logger. If `debug` is non-zero or the WG_DEBUG env var is
 * set, DEBUG messages are emitted. */
void logger_init(int debug);

void log_msg(log_level_t lvl, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

#define LOG_D(...) log_msg(LOG_DEBUG, __VA_ARGS__)
#define LOG_I(...) log_msg(LOG_INFO,  __VA_ARGS__)
#define LOG_W(...) log_msg(LOG_WARN,  __VA_ARGS__)
#define LOG_E(...) log_msg(LOG_ERR,   __VA_ARGS__)

#endif
