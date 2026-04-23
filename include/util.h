#ifndef WGATECTL_UTIL_H
#define WGATECTL_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

/* Parse "a.b.c.d" into host-order uint32. Returns true on success. */
bool ip_parse(const char *s, uint32_t *out);

/* Parse "a.b.c.d/N" into network addr (host-order) + mask. Returns true on
 * success. Accepts "a.b.c.d" with implied /32. */
bool cidr_parse(const char *s, uint32_t *addr, uint32_t *mask);

/* Format host-order IP into "a.b.c.d". Buffer must be >= 16 bytes. */
void ip_format(uint32_t ip, char *buf);

/* True iff ip (host-order) lies in [addr,addr|~mask]. */
bool ip_in_subnet(uint32_t ip, uint32_t addr, uint32_t mask);

/* Parse dotted-MAC "aa:bb:cc:dd:ee:ff" into 6 bytes. Returns true on success. */
bool mac_parse(const char *s, uint8_t out[6]);

/* Format MAC bytes into "aa:bb:cc:dd:ee:ff". Buffer must be >= 18 bytes. */
void mac_format(const uint8_t mac[6], char *buf);

/* Monotonic time in nanoseconds. */
uint64_t now_mono_ns(void);

/* Wall-clock time in seconds (UTC epoch). */
int64_t now_wall_s(void);

/* Local-time ISO-8601 with offset, e.g. "2026-04-20T15:43:00-07:00".
 * Buffer must be >= 32 bytes. */
void now_wall_iso8601(char *buf, size_t cap);

/* Format a unix timestamp (seconds) as local-time ISO-8601 with offset. */
void ts_iso8601(int64_t secs, char *buf, size_t cap);

/* Local-time "YYYYMMDD" for the current wall clock. Buffer must be >= 9. */
void now_ymd(char *buf, size_t cap);

/* Local-time HHMM + weekday (0..6, Sun=0). */
void now_hm_wday(int *hm, int *wday);

/* Read a small file into a heap-allocated NUL-terminated buffer. On success
 * returns the buffer (free() to release) and sets *len; on failure returns
 * NULL. Max `limit` bytes; if the file is longer, truncates and still
 * succeeds. */
char *read_small_file(const char *path, size_t limit, size_t *out_len);

/* Atomically replace `path` with the bytes in [data, data+len). Uses a
 * sibling tmp file + rename. Returns 0 on success, -1 on failure. */
int atomic_write(const char *path, const void *data, size_t len);

/* strdup but with NULL tolerance and error return. */
char *xstrdup(const char *s);

/* Recursively create a directory path (like `mkdir -p`). Mode is used
 * for any components that have to be created. Returns 0 on success or if
 * the directory already exists, -1 otherwise. */
int mkdir_p(const char *path, int mode);

/* Find an executable. If `hint` is absolute and points at a file that is
 * accessible with X_OK, that path is written into `out`. Otherwise tries
 * the usual sbin/bin locations for the given `name`. Returns true if a
 * path was written to out (NUL-terminated, <= cap bytes). */
bool resolve_bin(const char *hint, const char *name, char *out, size_t cap);

#endif
