#ifndef WGATECTL_JSONL_H
#define WGATECTL_JSONL_H

#include <stdbool.h>
#include <stddef.h>

typedef struct jsonl jsonl_t;

/* Open the writer. `dir` is the directory; filenames are
 * events-YYYYMMDD.jsonl relative to it. `retain_days` removes files older
 * than that many calendar days on each rotation (set <= 0 to disable). */
jsonl_t *jsonl_open(const char *dir, int retain_days);

/* Append one line (the caller's JSON text, no trailing newline). */
int jsonl_append(jsonl_t *j, const char *buf, size_t len);

/* Periodic fdatasync (call every ~60 s). */
int jsonl_sync(jsonl_t *j);

/* Tail the current day's file starting at offset-or-timestamp.
 * If since_ts is > 0 it scans backwards over the current file to skip any
 * lines whose unix "ts" second is <= since_ts. The callback receives one
 * line at a time (no trailing newline). It is invoked with the writer's
 * FILE flushed (all pending lines visible). Returns 0 on success. */
int jsonl_tail(jsonl_t *j, long since_ts,
               int (*cb)(void *ctx, const char *line, size_t len),
               void *ctx);

/* Fsync on shutdown and close file descriptors. */
void jsonl_close(jsonl_t *j);

#endif
