#include "json.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* =====================  emitter  ===================== */

static void out_reserve(json_out_t *j, size_t extra) {
    if (j->len + extra + 1 <= j->cap) return;
    size_t ncap = j->cap ? j->cap : 256;
    while (ncap < j->len + extra + 1) ncap *= 2;
    char *nb = realloc(j->buf, ncap);
    if (!nb) { free(j->buf); j->buf = NULL; j->cap = j->len = 0; return; }
    j->buf = nb;
    j->cap = ncap;
}

static void out_putc(json_out_t *j, char c) {
    out_reserve(j, 1);
    if (!j->buf) return;
    j->buf[j->len++] = c;
    j->buf[j->len] = 0;
}

static void out_puts(json_out_t *j, const char *s) {
    size_t n = strlen(s);
    out_reserve(j, n);
    if (!j->buf) return;
    memcpy(j->buf + j->len, s, n);
    j->len += n;
    j->buf[j->len] = 0;
}

void json_out_init(json_out_t *j) {
    memset(j, 0, sizeof(*j));
}

void json_out_free(json_out_t *j) {
    free(j->buf);
    memset(j, 0, sizeof(*j));
}

/* emit a separator ("," or ":") if needed before the next value */
static void sep_before_value(json_out_t *j) {
    if (j->depth == 0) return;
    if (j->in_obj[j->depth - 1]) return; /* object: key prints the comma */
    if (j->first[j->depth - 1]) {
        j->first[j->depth - 1] = 0;
    } else {
        out_putc(j, ',');
    }
}

static void emit_string(json_out_t *j, const char *s) {
    out_putc(j, '"');
    if (!s) { out_putc(j, '"'); return; }
    const unsigned char *p = (const unsigned char *)s;
    for (; *p; p++) {
        unsigned char c = *p;
        switch (c) {
            case '"':  out_puts(j, "\\\""); break;
            case '\\': out_puts(j, "\\\\"); break;
            case '\b': out_puts(j, "\\b");  break;
            case '\f': out_puts(j, "\\f");  break;
            case '\n': out_puts(j, "\\n");  break;
            case '\r': out_puts(j, "\\r");  break;
            case '\t': out_puts(j, "\\t");  break;
            default:
                if (c < 0x20) {
                    char esc[8];
                    snprintf(esc, sizeof(esc), "\\u%04x", c);
                    out_puts(j, esc);
                } else {
                    out_putc(j, (char)c);
                }
        }
    }
    out_putc(j, '"');
}

void json_obj_begin(json_out_t *j) {
    sep_before_value(j);
    out_putc(j, '{');
    if (j->depth < (int)sizeof(j->in_obj)) {
        j->in_obj[j->depth] = 1;
        j->first [j->depth] = 1;
        j->depth++;
    }
}

void json_obj_end(json_out_t *j) {
    if (j->depth > 0) j->depth--;
    out_putc(j, '}');
}

void json_arr_begin(json_out_t *j) {
    sep_before_value(j);
    out_putc(j, '[');
    if (j->depth < (int)sizeof(j->in_obj)) {
        j->in_obj[j->depth] = 0;
        j->first [j->depth] = 1;
        j->depth++;
    }
}

void json_arr_end(json_out_t *j) {
    if (j->depth > 0) j->depth--;
    out_putc(j, ']');
}

void json_key(json_out_t *j, const char *k) {
    if (j->depth == 0 || !j->in_obj[j->depth - 1]) return;
    if (j->first[j->depth - 1]) {
        j->first[j->depth - 1] = 0;
    } else {
        out_putc(j, ',');
    }
    emit_string(j, k);
    out_putc(j, ':');
}

void json_str(json_out_t *j, const char *v) {
    sep_before_value(j);
    emit_string(j, v);
}

void json_raw(json_out_t *j, const char *raw) {
    sep_before_value(j);
    out_puts(j, raw);
}

void json_i64(json_out_t *j, int64_t v) {
    sep_before_value(j);
    char buf[32];
    snprintf(buf, sizeof(buf), "%lld", (long long)v);
    out_puts(j, buf);
}

void json_u64(json_out_t *j, uint64_t v) {
    sep_before_value(j);
    char buf[32];
    snprintf(buf, sizeof(buf), "%llu", (unsigned long long)v);
    out_puts(j, buf);
}

void json_f64(json_out_t *j, double v, int decimals) {
    sep_before_value(j);
    if (decimals < 0) decimals = 2;
    if (decimals > 9) decimals = 9;
    char buf[48];
    snprintf(buf, sizeof(buf), "%.*f", decimals, v);
    out_puts(j, buf);
}

void json_bool(json_out_t *j, bool v) {
    sep_before_value(j);
    out_puts(j, v ? "true" : "false");
}

void json_null(json_out_t *j) {
    sep_before_value(j);
    out_puts(j, "null");
}

void json_kstr (json_out_t *j, const char *k, const char *v) { json_key(j, k); json_str(j, v); }
void json_ki64 (json_out_t *j, const char *k, int64_t v)     { json_key(j, k); json_i64(j, v); }
void json_ku64 (json_out_t *j, const char *k, uint64_t v)    { json_key(j, k); json_u64(j, v); }
void json_kf64 (json_out_t *j, const char *k, double v, int d){ json_key(j, k); json_f64(j, v, d); }
void json_kbool(json_out_t *j, const char *k, bool v)        { json_key(j, k); json_bool(j, v); }
void json_knull(json_out_t *j, const char *k)                { json_key(j, k); json_null(j); }

/* =====================  parser  ===================== */

typedef struct {
    const char *s;
    const char *end;
    const char *err;
    int depth;
} pctx_t;

#define PMAX_DEPTH 32

static void skip_ws(pctx_t *p) {
    while (p->s < p->end) {
        char c = *p->s;
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') p->s++;
        else break;
    }
}

static bool parse_value(pctx_t *p, json_val_t *out);

static bool parse_string(pctx_t *p, char **out_s, size_t *out_n) {
    if (p->s >= p->end || *p->s != '"') { p->err = "expected string"; return false; }
    p->s++;
    /* single-pass: compute length, then allocate, then copy */
    const char *begin = p->s;
    size_t len = 0;
    while (p->s < p->end && *p->s != '"') {
        if (*p->s == '\\') {
            if (p->s + 1 >= p->end) { p->err = "bad escape"; return false; }
            char e = p->s[1];
            if (e == 'u') {
                if (p->s + 6 > p->end) { p->err = "bad \\u"; return false; }
                p->s += 6;
                len += 4; /* worst-case UTF-8 for a single BMP code point */
            } else {
                p->s += 2;
                len += 1;
            }
        } else {
            p->s++;
            len++;
        }
    }
    if (p->s >= p->end) { p->err = "unterminated string"; return false; }
    const char *finish = p->s;
    p->s++; /* skip closing quote */

    char *buf = malloc(len + 1);
    if (!buf) { p->err = "oom"; return false; }
    size_t n = 0;
    for (const char *q = begin; q < finish; ) {
        if (*q == '\\') {
            char e = q[1];
            switch (e) {
                case '"': buf[n++] = '"'; q += 2; break;
                case '\\': buf[n++] = '\\'; q += 2; break;
                case '/': buf[n++] = '/'; q += 2; break;
                case 'b': buf[n++] = '\b'; q += 2; break;
                case 'f': buf[n++] = '\f'; q += 2; break;
                case 'n': buf[n++] = '\n'; q += 2; break;
                case 'r': buf[n++] = '\r'; q += 2; break;
                case 't': buf[n++] = '\t'; q += 2; break;
                case 'u': {
                    unsigned cp = 0;
                    for (int i = 0; i < 4; i++) {
                        char h = q[2 + i];
                        cp <<= 4;
                        if      (h >= '0' && h <= '9') cp |= (unsigned)(h - '0');
                        else if (h >= 'a' && h <= 'f') cp |= (unsigned)(h - 'a' + 10);
                        else if (h >= 'A' && h <= 'F') cp |= (unsigned)(h - 'A' + 10);
                        else { free(buf); p->err = "bad \\u hex"; return false; }
                    }
                    if (cp < 0x80) {
                        buf[n++] = (char)cp;
                    } else if (cp < 0x800) {
                        buf[n++] = (char)(0xC0 | (cp >> 6));
                        buf[n++] = (char)(0x80 | (cp & 0x3F));
                    } else {
                        buf[n++] = (char)(0xE0 | (cp >> 12));
                        buf[n++] = (char)(0x80 | ((cp >> 6) & 0x3F));
                        buf[n++] = (char)(0x80 | (cp & 0x3F));
                    }
                    q += 6;
                    break;
                }
                default: free(buf); p->err = "bad escape"; return false;
            }
        } else {
            buf[n++] = *q++;
        }
    }
    buf[n] = 0;
    *out_s = buf;
    *out_n = n;
    return true;
}

static bool parse_number(pctx_t *p, double *out) {
    char tmp[64];
    size_t i = 0;
    while (p->s < p->end && i + 1 < sizeof(tmp)) {
        char c = *p->s;
        if ((c >= '0' && c <= '9') || c == '-' || c == '+' ||
            c == '.' || c == 'e' || c == 'E') {
            tmp[i++] = c;
            p->s++;
        } else break;
    }
    tmp[i] = 0;
    if (i == 0) { p->err = "expected number"; return false; }
    char *endp = NULL;
    double v = strtod(tmp, &endp);
    if (!endp || *endp != 0) { p->err = "bad number"; return false; }
    *out = v;
    return true;
}

static bool match_keyword(pctx_t *p, const char *kw) {
    size_t n = strlen(kw);
    if ((size_t)(p->end - p->s) < n) return false;
    if (memcmp(p->s, kw, n) != 0) return false;
    p->s += n;
    return true;
}

static bool parse_array(pctx_t *p, json_val_t *out) {
    p->s++; /* skip [ */
    skip_ws(p);
    out->type = JV_ARR;
    out->u.arr.items = NULL;
    out->u.arr.n = 0;
    size_t cap = 0;
    if (p->s < p->end && *p->s == ']') { p->s++; return true; }

    while (p->s < p->end) {
        if (out->u.arr.n == cap) {
            cap = cap ? cap * 2 : 4;
            json_val_t *ni = realloc(out->u.arr.items, cap * sizeof(*ni));
            if (!ni) { p->err = "oom"; return false; }
            out->u.arr.items = ni;
        }
        if (!parse_value(p, &out->u.arr.items[out->u.arr.n])) return false;
        out->u.arr.n++;
        skip_ws(p);
        if (p->s >= p->end) { p->err = "unterminated array"; return false; }
        if (*p->s == ',') { p->s++; skip_ws(p); continue; }
        if (*p->s == ']') { p->s++; return true; }
        p->err = "expected , or ]";
        return false;
    }
    p->err = "unterminated array";
    return false;
}

static bool parse_object(pctx_t *p, json_val_t *out) {
    p->s++; /* skip { */
    skip_ws(p);
    out->type = JV_OBJ;
    out->u.obj.keys = NULL;
    out->u.obj.vals = NULL;
    out->u.obj.n = 0;
    size_t cap = 0;
    if (p->s < p->end && *p->s == '}') { p->s++; return true; }

    while (p->s < p->end) {
        if (out->u.obj.n == cap) {
            cap = cap ? cap * 2 : 4;
            char **nk = realloc(out->u.obj.keys, cap * sizeof(*nk));
            if (!nk) { p->err = "oom"; return false; }
            out->u.obj.keys = nk;
            json_val_t *nv = realloc(out->u.obj.vals, cap * sizeof(*nv));
            if (!nv) { p->err = "oom"; return false; }
            out->u.obj.vals = nv;
        }
        skip_ws(p);
        char *k = NULL; size_t klen = 0;
        if (!parse_string(p, &k, &klen)) return false;
        out->u.obj.keys[out->u.obj.n] = k;
        skip_ws(p);
        if (p->s >= p->end || *p->s != ':') { p->err = "expected :"; return false; }
        p->s++;
        skip_ws(p);
        if (!parse_value(p, &out->u.obj.vals[out->u.obj.n])) return false;
        out->u.obj.n++;
        skip_ws(p);
        if (p->s >= p->end) { p->err = "unterminated object"; return false; }
        if (*p->s == ',') { p->s++; skip_ws(p); continue; }
        if (*p->s == '}') { p->s++; return true; }
        p->err = "expected , or }";
        return false;
    }
    p->err = "unterminated object";
    return false;
}

static bool parse_value(pctx_t *p, json_val_t *out) {
    skip_ws(p);
    if (p->s >= p->end) { p->err = "unexpected EOF"; return false; }
    if (p->depth >= PMAX_DEPTH) { p->err = "too deep"; return false; }
    p->depth++;
    bool ok = false;
    char c = *p->s;
    if (c == '{') {
        ok = parse_object(p, out);
    } else if (c == '[') {
        ok = parse_array(p, out);
    } else if (c == '"') {
        char *s = NULL; size_t n = 0;
        ok = parse_string(p, &s, &n);
        if (ok) { out->type = JV_STR; out->u.str.s = s; out->u.str.n = n; }
    } else if (c == 't' || c == 'f') {
        if (match_keyword(p, "true"))       { out->type = JV_BOOL; out->u.b = 1; ok = true; }
        else if (match_keyword(p, "false")) { out->type = JV_BOOL; out->u.b = 0; ok = true; }
        else p->err = "bad literal";
    } else if (c == 'n') {
        if (match_keyword(p, "null")) { out->type = JV_NULL; ok = true; }
        else p->err = "bad literal";
    } else if (c == '-' || (c >= '0' && c <= '9')) {
        double v = 0;
        ok = parse_number(p, &v);
        if (ok) { out->type = JV_NUM; out->u.n = v; }
    } else {
        p->err = "unexpected character";
    }
    p->depth--;
    return ok;
}

json_val_t *json_parse(const char *s, size_t n, const char **err) {
    json_val_t *v = calloc(1, sizeof(*v));
    if (!v) { if (err) *err = "oom"; return NULL; }
    pctx_t p = { .s = s, .end = s + n, .err = NULL, .depth = 0 };
    if (!parse_value(&p, v)) {
        if (err) *err = p.err ? p.err : "parse error";
        json_val_free(v);
        return NULL;
    }
    skip_ws(&p);
    if (p.s != p.end) {
        if (err) *err = "trailing data";
        json_val_free(v);
        return NULL;
    }
    return v;
}

/* Free the contents of an inline json_val_t but NOT the struct itself. */
static void jv_free_inline(json_val_t *v) {
    if (!v) return;
    switch (v->type) {
        case JV_STR:
            free(v->u.str.s);
            break;
        case JV_ARR:
            for (size_t i = 0; i < v->u.arr.n; i++)
                jv_free_inline(&v->u.arr.items[i]);
            free(v->u.arr.items);
            break;
        case JV_OBJ:
            for (size_t i = 0; i < v->u.obj.n; i++) {
                free(v->u.obj.keys[i]);
                jv_free_inline(&v->u.obj.vals[i]);
            }
            free(v->u.obj.keys);
            free(v->u.obj.vals);
            break;
        default:
            break;
    }
    v->type = JV_NULL;
}

void json_val_free(json_val_t *v) {
    if (!v) return;
    jv_free_inline(v);
    free(v);
}

const json_val_t *json_obj_get(const json_val_t *v, const char *key) {
    if (!v || v->type != JV_OBJ) return NULL;
    for (size_t i = 0; i < v->u.obj.n; i++) {
        if (strcmp(v->u.obj.keys[i], key) == 0) return &v->u.obj.vals[i];
    }
    return NULL;
}

bool json_get_i64(const json_val_t *v, int64_t *out) {
    if (!v || v->type != JV_NUM) return false;
    *out = (int64_t)v->u.n;
    return true;
}

bool json_get_str(const json_val_t *v, const char **out) {
    if (!v || v->type != JV_STR) return false;
    *out = v->u.str.s;
    return true;
}

bool json_get_bool(const json_val_t *v, bool *out) {
    if (!v || v->type != JV_BOOL) return false;
    *out = v->u.b ? true : false;
    return true;
}
