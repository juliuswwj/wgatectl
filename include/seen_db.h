#ifndef WGATECTL_SEEN_DB_H
#define WGATECTL_SEEN_DB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Persistent first_seen/last_seen-by-MAC map, used so that the daemon
 * can answer "when did we first see this device?" even after a restart.
 * Backed by a small JSON file written atomically. */

typedef struct wg_seen_db wg_seen_db_t;

/* Open the database. `path` is the JSON file (e.g.
 * /opt/wgatectl/hosts.json). If the file doesn't exist yet the db starts
 * empty; the parent directory is created on demand at save time. NULL or
 * empty `path` produces an in-memory-only db (saves are no-ops). */
wg_seen_db_t *seen_db_open(const char *path);
void          seen_db_close(wg_seen_db_t *db);

/* Look up `mac`. On hit fills first_seen/last_seen (epoch seconds) and
 * returns true. Either out-pointer may be NULL. */
bool seen_db_get(const wg_seen_db_t *db, const uint8_t mac[6],
                 int64_t *first_seen, int64_t *last_seen);

/* Mark `mac` as observed at `now`. Inserts (first_seen=last_seen=now) if
 * the MAC is new; otherwise just bumps last_seen. Returns 1 if a new
 * row was created, 0 otherwise. Marks the db dirty either way. */
int seen_db_observe(wg_seen_db_t *db, const uint8_t mac[6], int64_t now);

/* Atomically rewrite the on-disk JSON; clears the dirty flag on success.
 * Returns 0 on success, -1 on I/O error. No-op (returns 0) if the db has
 * no path or is not dirty. */
int  seen_db_save(wg_seen_db_t *db);

bool seen_db_dirty(const wg_seen_db_t *db);

#endif
