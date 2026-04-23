#ifndef WGATECTL_JSON_H
#define WGATECTL_JSON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ---- emitter: append-to-buffer, no allocation per primitive ---- */

typedef struct {
    char  *buf;
    size_t len;
    size_t cap;
    /* stack of frames: bit 0 = in object (1) or array (0),
     * and we track whether a comma is needed via at_start[] */
    int    depth;
    unsigned char in_obj[32];
    unsigned char first[32];
} json_out_t;

void json_out_init(json_out_t *j);
void json_out_free(json_out_t *j);

void json_obj_begin(json_out_t *j);
void json_obj_end  (json_out_t *j);
void json_arr_begin(json_out_t *j);
void json_arr_end  (json_out_t *j);

void json_key  (json_out_t *j, const char *k);
void json_str  (json_out_t *j, const char *v);
void json_raw  (json_out_t *j, const char *raw);  /* caller-escaped */
void json_i64  (json_out_t *j, int64_t v);
void json_u64  (json_out_t *j, uint64_t v);
void json_f64  (json_out_t *j, double v, int decimals);
void json_bool (json_out_t *j, bool v);
void json_null (json_out_t *j);

/* key+value convenience — must be inside an object frame */
void json_kstr (json_out_t *j, const char *k, const char *v);
void json_ki64 (json_out_t *j, const char *k, int64_t v);
void json_ku64 (json_out_t *j, const char *k, uint64_t v);
void json_kf64 (json_out_t *j, const char *k, double v, int decimals);
void json_kbool(json_out_t *j, const char *k, bool v);
void json_knull(json_out_t *j, const char *k);

/* ---- parser: minimal DOM for small request bodies ---- */

typedef enum {
    JV_NULL,
    JV_BOOL,
    JV_NUM,
    JV_STR,
    JV_ARR,
    JV_OBJ
} json_type_t;

typedef struct json_val {
    json_type_t type;
    union {
        int    b;
        double n;
        struct { char   *s; size_t n; }          str;
        struct { struct json_val *items; size_t n; } arr;
        struct {
            char            **keys;   /* NUL-terminated, owned */
            struct json_val  *vals;
            size_t            n;
        } obj;
    } u;
} json_val_t;

/* Parse bytes [s, s+n). On error returns NULL and sets *err (optional) to a
 * short static string. Returned value must be freed with json_val_free. */
json_val_t *json_parse(const char *s, size_t n, const char **err);
void        json_val_free(json_val_t *v);

/* Typed access helpers */
const json_val_t *json_obj_get(const json_val_t *v, const char *key);
bool json_get_i64(const json_val_t *v, int64_t *out);
bool json_get_str(const json_val_t *v, const char **out);
bool json_get_bool(const json_val_t *v, bool *out);

#endif
