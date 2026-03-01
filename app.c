#define _GNU_SOURCE
#include "mysql_wire.h"
#include "template_engine.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    const char *sphinx_host;
    uint16_t sphinx_port;
    const char *home;
    const char *template_dir;
    int overview_limit;
    const char *overview_order;
    const char *stamps_csv;
    int listen_port;
    const char *listen_host;
    const char *db_user;
    const char *db_password;
    const char *db_name;
} Config;

typedef struct {
    char *name;
    char *value;
} KV;

typedef struct {
    KV *items;
    size_t len;
    size_t cap;
} KVList;

typedef struct {
    int fd;
    char method[8];
    char path[2048];
    char query[4096];
    char content_type[512];
    size_t content_length;
    unsigned char *body;
} Request;

typedef struct {
    int status;
    const char *ctype;
    unsigned char *body;
    size_t body_len;
} Response;

typedef struct {
    long long id;
    char *title;
    char *tags;
} Doc;

typedef struct {
    Doc *items;
    size_t len;
    size_t cap;
} DocList;

typedef struct {
    char *tag;
    long long added;
    long long removed;
    int has_removed;
} TagRec;

typedef struct {
    TagRec *items;
    size_t len;
    size_t cap;
} TagList;

typedef struct {
    const char *data;
    size_t len;
    size_t pos;
} JsonIn;

static Config g_cfg;
static int g_debug = 0;

static void response_set_text(Response *r, int status, const char *ctype, const char *text);

static void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

static const char *envs(const char *k, const char *defv) {
    const char *v = getenv(k);
    return (v && *v) ? v : defv;
}

static int envi(const char *k, int defv) {
    const char *v = getenv(k);
    if (!v || !*v) return defv;
    char *end = NULL;
    long n = strtol(v, &end, 10);
    if (!end || *end) return defv;
    return (int)n;
}

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long long)ts.tv_sec * 1000LL + (long long)(ts.tv_nsec / 1000000LL);
}

static long long now_s(void) {
    return (long long)time(NULL);
}

static void log_msg(const char *fmt, ...) {
    if (!g_debug) return;
    time_t t = time(NULL);
    struct tm tmv;
    localtime_r(&t, &tmv);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tmv);
    fprintf(stderr, "[%s] ", ts);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    fflush(stderr);
}

static void kvl_init(KVList *l) {
    memset(l, 0, sizeof(*l));
}

static void kvl_free(KVList *l) {
    for (size_t i = 0; i < l->len; i++) {
        free(l->items[i].name);
        free(l->items[i].value);
    }
    free(l->items);
    memset(l, 0, sizeof(*l));
}

static int kvl_add(KVList *l, const char *k, const char *v) {
    if (l->len == l->cap) {
        size_t nc = l->cap ? l->cap * 2 : 16;
        KV *ni = realloc(l->items, nc * sizeof(KV));
        if (!ni) return -1;
        l->items = ni;
        l->cap = nc;
    }
    l->items[l->len].name = strdup(k ? k : "");
    l->items[l->len].value = strdup(v ? v : "");
    if (!l->items[l->len].name || !l->items[l->len].value) return -1;
    l->len++;
    return 0;
}

static const char *kvl_get(const KVList *l, const char *k) {
    for (size_t i = 0; i < l->len; i++) {
        if (strcmp(l->items[i].name, k) == 0) return l->items[i].value;
    }
    return NULL;
}

static int hexv(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    return -1;
}

static char *url_decode(const char *s) {
    size_t n = strlen(s);
    char *o = malloc(n + 1);
    if (!o) return NULL;
    size_t j = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] == '+') {
            o[j++] = ' ';
        } else if (s[i] == '%' && i + 2 < n) {
            int a = hexv(s[i + 1]);
            int b = hexv(s[i + 2]);
            if (a >= 0 && b >= 0) {
                o[j++] = (char)((a << 4) | b);
                i += 2;
            } else {
                o[j++] = s[i];
            }
        } else {
            o[j++] = s[i];
        }
    }
    o[j] = 0;
    return o;
}

static int parse_urlencoded(const char *s, KVList *out) {
    kvl_init(out);
    if (!s || !*s) return 0;
    const char *p = s;
    while (*p) {
        const char *amp = strchr(p, '&');
        size_t seglen = amp ? (size_t)(amp - p) : strlen(p);
        char *seg = strndup(p, seglen);
        if (!seg) return -1;
        char *eq = strchr(seg, '=');
        if (eq) {
            *eq = 0;
            char *dk = url_decode(seg);
            char *dv = url_decode(eq + 1);
            if (!dk || !dv || kvl_add(out, dk, dv) != 0) {
                free(seg);
                free(dk);
                free(dv);
                return -1;
            }
            free(dk);
            free(dv);
        } else {
            char *dk = url_decode(seg);
            if (!dk || kvl_add(out, dk, "") != 0) {
                free(seg);
                free(dk);
                return -1;
            }
            free(dk);
        }
        free(seg);
        if (!amp) break;
        p = amp + 1;
    }
    return 0;
}

static char *trim_dup(const char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1])) n--;
    return strndup(s, n);
}

static int contains_ws(const char *s) {
    for (; *s; s++) if (isspace((unsigned char)*s)) return 1;
    return 0;
}

static int ensure_dir(const char *path) {
    char tmp[PATH_MAX];
    if (strlen(path) >= sizeof(tmp)) return -1;
    strcpy(tmp, path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

static char *path_join3(const char *a, const char *b, const char *c) {
    size_t n = strlen(a) + strlen(b) + strlen(c) + 3;
    char *o = malloc(n);
    if (!o) return NULL;
    snprintf(o, n, "%s/%s%s", a, b, c);
    return o;
}

static char *path_join2(const char *a, const char *b) {
    size_t n = strlen(a) + strlen(b) + 2;
    char *o = malloc(n);
    if (!o) return NULL;
    snprintf(o, n, "%s/%s", a, b);
    return o;
}

static int read_file_all(const char *path, unsigned char **out, size_t *out_len) {
    *out = NULL;
    *out_len = 0;
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    long n = ftell(f);
    if (n < 0) {
        fclose(f);
        return -1;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }
    unsigned char *buf = malloc((size_t)n + 1);
    if (!buf) {
        fclose(f);
        return -1;
    }
    size_t rd = fread(buf, 1, (size_t)n, f);
    fclose(f);
    if (rd != (size_t)n) {
        free(buf);
        return -1;
    }
    buf[n] = 0;
    *out = buf;
    *out_len = (size_t)n;
    return 0;
}

static int write_file_all(const char *path, const void *buf, size_t len) {
    char tmp[PATH_MAX];
    if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp)) return -1;
    FILE *f = fopen(tmp, "wb");
    if (!f) return -1;
    if (len && fwrite(buf, 1, len, f) != len) {
        fclose(f);
        unlink(tmp);
        return -1;
    }
    if (fclose(f) != 0) {
        unlink(tmp);
        return -1;
    }
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

static void sb_appendf(char **buf, size_t *len, size_t *cap, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int need = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (need < 0) return;
    size_t nneed = (size_t)need;
    if (*len + nneed + 1 > *cap) {
        size_t nc = *cap ? *cap : 1024;
        while (*len + nneed + 1 > nc) nc *= 2;
        char *nb = realloc(*buf, nc);
        if (!nb) return;
        *buf = nb;
        *cap = nc;
    }
    va_start(ap, fmt);
    vsnprintf(*buf + *len, *cap - *len, fmt, ap);
    va_end(ap);
    *len += nneed;
}

static char *html_escape(const char *s) {
    size_t cap = strlen(s) * 6 + 1;
    char *o = malloc(cap);
    if (!o) return NULL;
    size_t j = 0;
    for (size_t i = 0; s[i]; i++) {
        switch (s[i]) {
            case '&': memcpy(o + j, "&amp;", 5); j += 5; break;
            case '<': memcpy(o + j, "&lt;", 4); j += 4; break;
            case '>': memcpy(o + j, "&gt;", 4); j += 4; break;
            case '"': memcpy(o + j, "&quot;", 6); j += 6; break;
            case '\'': memcpy(o + j, "&#39;", 5); j += 5; break;
            default: o[j++] = s[i]; break;
        }
    }
    o[j] = 0;
    return o;
}

static char *json_escape(const char *s) {
    size_t cap = strlen(s) * 6 + 1;
    char *o = malloc(cap);
    if (!o) return NULL;
    size_t j = 0;
    for (size_t i = 0; s[i]; i++) {
        unsigned char ch = (unsigned char)s[i];
        switch (ch) {
            case '"': o[j++]='\\'; o[j++]='"'; break;
            case '\\': o[j++]='\\'; o[j++]='\\'; break;
            case '\b': o[j++]='\\'; o[j++]='b'; break;
            case '\f': o[j++]='\\'; o[j++]='f'; break;
            case '\n': o[j++]='\\'; o[j++]='n'; break;
            case '\r': o[j++]='\\'; o[j++]='r'; break;
            case '\t': o[j++]='\\'; o[j++]='t'; break;
            default:
                if (ch < 0x20) {
                    j += (size_t)snprintf(o + j, cap - j, "\\u%04x", ch);
                } else {
                    o[j++] = (char)ch;
                }
                break;
        }
    }
    o[j] = 0;
    return o;
}

static int render_template(const char *name, const KVList *vars, Response *resp) {
    const char **keys = calloc(vars->len, sizeof(char *));
    const char **vals = calloc(vars->len, sizeof(char *));
    if (!keys || !vals) {
        free(keys);
        free(vals);
        return -1;
    }
    for (size_t i = 0; i < vars->len; i++) {
        keys[i] = vars->items[i].name;
        vals[i] = vars->items[i].value ? vars->items[i].value : "";
    }
    char terr[256];
    char *html = tpl_render_file(g_cfg.template_dir, name, keys, vals, vars->len, terr, sizeof(terr));
    free(keys);
    free(vals);
    if (!html) {
        return -1;
    }
    response_set_text(resp, 200, "text/html; charset=utf-8", html);
    free(html);
    return 0;
}

static void taglist_init(TagList *t) { memset(t, 0, sizeof(*t)); }

static void taglist_free(TagList *t) {
    for (size_t i = 0; i < t->len; i++) free(t->items[i].tag);
    free(t->items);
    memset(t, 0, sizeof(*t));
}

static int taglist_add(TagList *t, const char *tag, long long added, int has_removed, long long removed) {
    if (t->len == t->cap) {
        size_t nc = t->cap ? t->cap * 2 : 8;
        TagRec *ni = realloc(t->items, nc * sizeof(TagRec));
        if (!ni) return -1;
        t->items = ni;
        t->cap = nc;
    }
    t->items[t->len].tag = strdup(tag ? tag : "");
    if (!t->items[t->len].tag) return -1;
    t->items[t->len].added = added;
    t->items[t->len].has_removed = has_removed;
    t->items[t->len].removed = removed;
    t->len++;
    return 0;
}

static void json_skip_ws(JsonIn *in) {
    while (in->pos < in->len && isspace((unsigned char)in->data[in->pos])) in->pos++;
}

static int json_expect(JsonIn *in, char c) {
    json_skip_ws(in);
    if (in->pos >= in->len || in->data[in->pos] != c) return -1;
    in->pos++;
    return 0;
}

static char *json_parse_string(JsonIn *in) {
    json_skip_ws(in);
    if (in->pos >= in->len || in->data[in->pos] != '"') return NULL;
    in->pos++;
    size_t cap = 64, len = 0;
    char *o = malloc(cap);
    if (!o) return NULL;
    while (in->pos < in->len) {
        char ch = in->data[in->pos++];
        if (ch == '"') {
            o[len] = 0;
            return o;
        }
        if (ch == '\\') {
            if (in->pos >= in->len) { free(o); return NULL; }
            char e = in->data[in->pos++];
            switch (e) {
                case '"': ch = '"'; break;
                case '\\': ch = '\\'; break;
                case '/': ch = '/'; break;
                case 'b': ch = '\b'; break;
                case 'f': ch = '\f'; break;
                case 'n': ch = '\n'; break;
                case 'r': ch = '\r'; break;
                case 't': ch = '\t'; break;
                case 'u':
                    if (in->pos + 4 > in->len) { free(o); return NULL; }
                    in->pos += 4;
                    ch = '?';
                    break;
                default:
                    free(o);
                    return NULL;
            }
        }
        if (len + 2 > cap) {
            cap *= 2;
            char *no = realloc(o, cap);
            if (!no) { free(o); return NULL; }
            o = no;
        }
        o[len++] = ch;
    }
    free(o);
    return NULL;
}

static int json_parse_int_or_null(JsonIn *in, int *is_null, long long *out) {
    json_skip_ws(in);
    if (in->pos + 4 <= in->len && strncmp(in->data + in->pos, "null", 4) == 0) {
        in->pos += 4;
        *is_null = 1;
        *out = 0;
        return 0;
    }
    *is_null = 0;
    int neg = 0;
    if (in->pos < in->len && in->data[in->pos] == '-') {
        neg = 1;
        in->pos++;
    }
    if (in->pos >= in->len || !isdigit((unsigned char)in->data[in->pos])) return -1;
    long long v = 0;
    while (in->pos < in->len && isdigit((unsigned char)in->data[in->pos])) {
        v = v * 10 + (in->data[in->pos] - '0');
        in->pos++;
    }
    *out = neg ? -v : v;
    return 0;
}

static int parse_tags_json(const char *json, TagList *out) {
    taglist_init(out);
    if (!json || !*json) return 0;
    JsonIn in = {.data = json, .len = strlen(json), .pos = 0};
    if (json_expect(&in, '[') != 0) return -1;
    json_skip_ws(&in);
    if (in.pos < in.len && in.data[in.pos] == ']') {
        in.pos++;
        return 0;
    }
    while (1) {
        if (json_expect(&in, '{') != 0) return -1;
        char *tag = NULL;
        long long added = 0, removed = 0;
        int has_added = 0, has_removed = 0;
        while (1) {
            char *key = json_parse_string(&in);
            if (!key) { free(tag); return -1; }
            if (json_expect(&in, ':') != 0) { free(key); free(tag); return -1; }
            if (strcmp(key, "tag") == 0) {
                tag = json_parse_string(&in);
                if (!tag) { free(key); return -1; }
            } else if (strcmp(key, "added") == 0) {
                int n = 0;
                if (json_parse_int_or_null(&in, &n, &added) != 0 || n) { free(key); free(tag); return -1; }
                has_added = 1;
            } else if (strcmp(key, "removed") == 0) {
                int n = 0;
                if (json_parse_int_or_null(&in, &n, &removed) != 0) { free(key); free(tag); return -1; }
                has_removed = !n;
            } else {
                json_skip_ws(&in);
                if (in.pos < in.len && in.data[in.pos] == '"') {
                    char *tmp = json_parse_string(&in);
                    free(tmp);
                } else {
                    int n = 0;
                    long long dummy = 0;
                    if (json_parse_int_or_null(&in, &n, &dummy) != 0) {
                        free(key);
                        free(tag);
                        return -1;
                    }
                }
            }
            free(key);
            json_skip_ws(&in);
            if (in.pos < in.len && in.data[in.pos] == ',') {
                in.pos++;
                continue;
            }
            if (in.pos < in.len && in.data[in.pos] == '}') {
                in.pos++;
                break;
            }
            free(tag);
            return -1;
        }
        if (!tag) tag = strdup("");
        if (!has_added) added = now_s();
        if (taglist_add(out, tag, added, has_removed, removed) != 0) {
            free(tag);
            return -1;
        }
        free(tag);

        json_skip_ws(&in);
        if (in.pos < in.len && in.data[in.pos] == ',') {
            in.pos++;
            continue;
        }
        if (in.pos < in.len && in.data[in.pos] == ']') {
            in.pos++;
            break;
        }
        return -1;
    }
    return 0;
}

static char *tags_to_json(const TagList *tags) {
    char *buf = NULL;
    size_t len = 0, cap = 0;
    sb_appendf(&buf, &len, &cap, "[");
    for (size_t i = 0; i < tags->len; i++) {
        char *e = json_escape(tags->items[i].tag ? tags->items[i].tag : "");
        if (!e) { free(buf); return NULL; }
        sb_appendf(&buf, &len, &cap, "%s{\"tag\":\"%s\",\"added\":%lld,\"removed\":", i ? "," : "", e, tags->items[i].added);
        if (tags->items[i].has_removed) sb_appendf(&buf, &len, &cap, "%lld", tags->items[i].removed);
        else sb_appendf(&buf, &len, &cap, "null");
        sb_appendf(&buf, &len, &cap, "}");
        free(e);
    }
    sb_appendf(&buf, &len, &cap, "]");
    if (!buf) return strdup("[]");
    return buf;
}

static char *active_tags_str(const TagList *tags) {
    char *buf = NULL;
    size_t len = 0, cap = 0;
    for (size_t i = 0; i < tags->len; i++) {
        if (tags->items[i].has_removed) continue;
        if (tags->items[i].tag && *tags->items[i].tag) {
            sb_appendf(&buf, &len, &cap, "%s%s", len ? " " : "", tags->items[i].tag);
        }
    }
    if (!buf) return strdup("");
    return buf;
}

static int read_tags_file(const char *pdf_path, TagList *tags) {
    char *path = malloc(strlen(pdf_path) + 6);
    if (!path) return -1;
    sprintf(path, "%s.tags", pdf_path);
    unsigned char *buf = NULL;
    size_t len = 0;
    int rc = read_file_all(path, &buf, &len);
    free(path);
    if (rc != 0) {
        taglist_init(tags);
        return 0;
    }
    int prc = parse_tags_json((char *)buf, tags);
    free(buf);
    if (prc != 0) {
        taglist_init(tags);
        return 0;
    }
    return 0;
}

static int write_tags_file(const char *pdf_path, const TagList *tags) {
    char *path = malloc(strlen(pdf_path) + 6);
    if (!path) return -1;
    sprintf(path, "%s.tags", pdf_path);
    char *json = tags_to_json(tags);
    if (!json) {
        free(path);
        return -1;
    }
    int rc = write_file_all(path, json, strlen(json));
    free(json);
    free(path);
    return rc;
}

static int db_connect(mw_conn *c, char *err, size_t err_len) {
    return mw_connect(c, g_cfg.sphinx_host, g_cfg.sphinx_port, g_cfg.db_user, g_cfg.db_password, g_cfg.db_name, err, err_len);
}

static int db_query_rows(const char *sql, mw_result *r, char *err, size_t err_len) {
    log_msg("db_query_rows: begin sql[%.120s]", sql ? sql : "");
    mw_conn c;
    if (db_connect(&c, err, err_len) != 0) return -1;
    int rc = mw_query(&c, sql, r, err, err_len);
    mw_close(&c);
    log_msg("db_query_rows: end rc=%d rows=%zu err=%s", rc, (rc == 0 && r) ? r->num_rows : 0, (err && *err) ? err : "");
    return rc;
}

static int db_exec(const char *sql, uint64_t *affected, char *err, size_t err_len) {
    log_msg("db_exec: begin sql[%.120s]", sql ? sql : "");
    mw_conn c;
    if (db_connect(&c, err, err_len) != 0) return -1;
    mw_result r;
    int rc = mw_query(&c, sql, &r, err, err_len);
    if (rc == 0 && affected) *affected = r.affected_rows;
    mw_result_free(&r);
    mw_close(&c);
    log_msg("db_exec: end rc=%d affected=%llu err=%s", rc, (unsigned long long)(affected ? *affected : 0), (err && *err) ? err : "");
    return rc;
}

static int doclist_add(DocList *d, long long id, const char *title, const char *tags) {
    if (d->len == d->cap) {
        size_t nc = d->cap ? d->cap * 2 : 16;
        Doc *ni = realloc(d->items, nc * sizeof(Doc));
        if (!ni) return -1;
        d->items = ni;
        d->cap = nc;
    }
    d->items[d->len].id = id;
    d->items[d->len].title = strdup(title ? title : "");
    d->items[d->len].tags = strdup(tags ? tags : "");
    if (!d->items[d->len].title || !d->items[d->len].tags) return -1;
    d->len++;
    return 0;
}

static void doclist_free(DocList *d) {
    for (size_t i = 0; i < d->len; i++) {
        free(d->items[i].title);
        free(d->items[i].tags);
    }
    free(d->items);
    memset(d, 0, sizeof(*d));
}

static int fetch_docs(const char *search, DocList *out, long long *cnt, char *err, size_t err_len) {
    memset(out, 0, sizeof(*out));
    *cnt = 0;

    char *esc_search = NULL;
    char sql[8192];
    if (search && *search) {
        esc_search = mw_escape_sql_literal(search);
        if (!esc_search) {
            snprintf(err, err_len, "OOM");
            return -1;
        }
        snprintf(sql, sizeof(sql), "SELECT id,title,tags FROM testrt WHERE MATCH('%s') ORDER BY id %s LIMIT %d", esc_search, g_cfg.overview_order, g_cfg.overview_limit);
    } else {
        snprintf(sql, sizeof(sql), "SELECT id,title,tags FROM testrt ORDER BY id %s LIMIT %d", g_cfg.overview_order, g_cfg.overview_limit);
    }

    mw_result r;
    if (db_query_rows(sql, &r, err, err_len) != 0) {
        free(esc_search);
        return -1;
    }
    free(esc_search);

    for (size_t i = 0; i < r.num_rows; i++) {
        long long id = atoll(r.rows[i][0] ? r.rows[i][0] : "0");
        const char *title = r.rows[i][1] ? r.rows[i][1] : "";
        const char *tags = r.rows[i][2] ? r.rows[i][2] : "";
        if (doclist_add(out, id, title, tags) != 0) {
            mw_result_free(&r);
            doclist_free(out);
            snprintf(err, err_len, "OOM");
            return -1;
        }
    }
    *cnt = (long long)r.num_rows;
    mw_result_free(&r);
    return 0;
}

static int fetch_doc_title_by_id(long long id, char **title, char *err, size_t err_len) {
    *title = NULL;
    char sql[256];
    snprintf(sql, sizeof(sql), "SELECT title FROM testrt WHERE id = %lld", id);
    mw_result r;
    if (db_query_rows(sql, &r, err, err_len) != 0) return -1;
    if (r.num_rows == 0) {
        mw_result_free(&r);
        return 1;
    }
    *title = strdup(r.rows[0][0] ? r.rows[0][0] : "");
    mw_result_free(&r);
    if (!*title) {
        snprintf(err, err_len, "OOM");
        return -1;
    }
    return 0;
}

static int fetch_doc_title_tags_by_id(long long id, char **title, char **tags, char *err, size_t err_len) {
    *title = NULL;
    *tags = NULL;
    char sql[256];
    snprintf(sql, sizeof(sql), "SELECT title,tags FROM testrt WHERE id = %lld", id);
    mw_result r;
    if (db_query_rows(sql, &r, err, err_len) != 0) return -1;
    if (r.num_rows == 0) {
        mw_result_free(&r);
        return 1;
    }
    *title = strdup(r.rows[0][0] ? r.rows[0][0] : "");
    *tags = strdup(r.rows[0][1] ? r.rows[0][1] : "");
    mw_result_free(&r);
    if (!*title || !*tags) {
        free(*title);
        free(*tags);
        *title = NULL;
        *tags = NULL;
        snprintf(err, err_len, "OOM");
        return -1;
    }
    return 0;
}

static int delete_doc_row(long long id, char *err, size_t err_len) {
    char sql[256];
    snprintf(sql, sizeof(sql), "DELETE FROM testrt WHERE id = %lld", id);
    return db_exec(sql, NULL, err, err_len);
}

static int insert_doc_row(long long id, const char *title, const char *content, const char *tags, char *err, size_t err_len) {
    char *et = mw_escape_sql_literal(title ? title : "");
    char *ec = mw_escape_sql_literal(content ? content : "");
    char *eg = mw_escape_sql_literal(tags ? tags : "");
    if (!et || !ec || !eg) {
        free(et); free(ec); free(eg);
        snprintf(err, err_len, "OOM");
        return -1;
    }
    size_t need = strlen(et) + strlen(ec) + strlen(eg) + 256;
    char *sql = malloc(need);
    if (!sql) {
        free(et); free(ec); free(eg);
        snprintf(err, err_len, "OOM");
        return -1;
    }
    snprintf(sql, need, "INSERT INTO testrt (id,gid,title,content,tags) VALUES (%lld,%lld,'%s','%s','%s')", id, id, et, ec, eg);
    int rc = db_exec(sql, NULL, err, err_len);
    free(sql);
    free(et); free(ec); free(eg);
    return rc;
}

static int count_docs(long long *count, char *err, size_t err_len) {
    *count = 0;
    mw_result r;
    if (db_query_rows("SELECT COUNT(*) FROM testrt", &r, err, err_len) != 0) return -1;
    if (r.num_rows > 0 && r.rows[0][0]) *count = atoll(r.rows[0][0]);
    mw_result_free(&r);
    return 0;
}

static long long date_to_base_id(int y, int m, int d) {
    struct tm t;
    memset(&t, 0, sizeof(t));
    t.tm_year = y - 1900;
    t.tm_mon = m - 1;
    t.tm_mday = d;
    time_t sec = timegm(&t);
    return (long long)sec * 1000LL;
}

static int find_free_id_for_date(int y, int m, int d, long long *new_id, char *err, size_t err_len) {
    long long base = date_to_base_id(y, m, d);
    char sql[512];
    snprintf(sql, sizeof(sql), "SELECT id FROM testrt WHERE id >= %lld AND id < %lld", base, base + 86400000LL);
    mw_result r;
    if (db_query_rows(sql, &r, err, err_len) != 0) return -1;

    size_t n = r.num_rows;
    long long *ids = calloc(n, sizeof(long long));
    if (!ids) {
        mw_result_free(&r);
        snprintf(err, err_len, "OOM");
        return -1;
    }
    for (size_t i = 0; i < n; i++) ids[i] = atoll(r.rows[i][0] ? r.rows[i][0] : "0");
    mw_result_free(&r);

    long long cand = base;
    for (;;) {
        int taken = 0;
        for (size_t i = 0; i < n; i++) {
            if (ids[i] == cand) {
                taken = 1;
                break;
            }
        }
        if (!taken) break;
        cand++;
    }
    free(ids);
    *new_id = cand;
    return 0;
}

static char *strip_eldoar_date_header(const char *content) {
    const char *p = content;
    if (strncmp(p, "ELDOAR-DATE:", 12) == 0) {
        const char *nl = strchr(p, '\n');
        if (nl) return strdup(nl + 1);
        return strdup("");
    }
    char *o = NULL;
    size_t olen = 0, ocap = 0;
    const char *cur = p;
    while (*cur) {
        const char *nl = strchr(cur, '\n');
        size_t len = nl ? (size_t)(nl - cur + 1) : strlen(cur);
        if (!(len >= 12 && strncmp(cur, "ELDOAR-DATE:", 12) == 0)) {
            if (olen + len + 1 > ocap) {
                size_t nc = ocap ? ocap * 2 : 256;
                while (olen + len + 1 > nc) nc *= 2;
                char *no = realloc(o, nc);
                if (!no) {
                    free(o);
                    return NULL;
                }
                o = no;
                ocap = nc;
            }
            memcpy(o + olen, cur, len);
            olen += len;
            o[olen] = 0;
        }
        if (!nl) break;
        cur = nl + 1;
    }
    if (!o) o = strdup("");
    return o;
}

static void response_init(Response *r) {
    memset(r, 0, sizeof(*r));
    r->status = 200;
    r->ctype = "text/plain; charset=utf-8";
}

static void response_set_text(Response *r, int status, const char *ctype, const char *text) {
    r->status = status;
    r->ctype = ctype;
    free(r->body);
    r->body_len = strlen(text);
    r->body = malloc(r->body_len + 1);
    if (!r->body) {
        r->body_len = 0;
        return;
    }
    memcpy(r->body, text, r->body_len + 1);
}

static void response_set_blob(Response *r, int status, const char *ctype, const unsigned char *blob, size_t len) {
    r->status = status;
    r->ctype = ctype;
    free(r->body);
    r->body = malloc(len);
    if (!r->body) {
        r->body_len = 0;
        return;
    }
    memcpy(r->body, blob, len);
    r->body_len = len;
}

static int send_response(int fd, const Response *r, const char *extra_headers) {
    const char *msg = "OK";
    if (r->status == 302) msg = "Found";
    else if (r->status == 400) msg = "Bad Request";
    else if (r->status == 404) msg = "Not Found";
    else if (r->status == 405) msg = "Method Not Allowed";
    else if (r->status == 413) msg = "Payload Too Large";
    else if (r->status == 500) msg = "Internal Server Error";

    char head[2048];
    int n = snprintf(head, sizeof(head),
        "HTTP/1.1 %d %s\r\n"
        "Connection: close\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "%s"
        "\r\n",
        r->status,
        msg,
        r->ctype ? r->ctype : "text/plain",
        r->body_len,
        extra_headers ? extra_headers : "");
    if (n <= 0 || (size_t)n >= sizeof(head)) return -1;

    if (send(fd, head, (size_t)n, 0) < 0) return -1;
    if (r->body_len > 0) {
        size_t off = 0;
        while (off < r->body_len) {
            ssize_t w = send(fd, r->body + off, r->body_len - off, 0);
            if (w < 0) return -1;
            off += (size_t)w;
        }
    }
    return 0;
}

static const char *guess_ctype(const char *path) {
    const char *dot = strrchr(path, '.');
    if (!dot) return "application/octet-stream";
    if (strcasecmp(dot, ".html") == 0) return "text/html; charset=utf-8";
    if (strcasecmp(dot, ".css") == 0) return "text/css; charset=utf-8";
    if (strcasecmp(dot, ".js") == 0) return "application/javascript; charset=utf-8";
    if (strcasecmp(dot, ".json") == 0) return "application/json; charset=utf-8";
    if (strcasecmp(dot, ".jpg") == 0 || strcasecmp(dot, ".jpeg") == 0) return "image/jpeg";
    if (strcasecmp(dot, ".png") == 0) return "image/png";
    if (strcasecmp(dot, ".pdf") == 0) return "application/pdf";
    if (strcasecmp(dot, ".svg") == 0) return "image/svg+xml";
    return "application/octet-stream";
}

static int path_is_safe_rel(const char *p) {
    if (!p || !*p) return 0;
    if (p[0] == '/') return 0;
    if (strstr(p, "..")) return 0;
    return 1;
}

static int req_read_all(int fd, unsigned char *buf, size_t n) {
    log_msg("req_read_all: want=%zu", n);
    size_t off = 0;
    while (off < n) {
        ssize_t r = recv(fd, buf + off, n - off, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            log_msg("req_read_all: recv error off=%zu errno=%d (%s)", off, errno, strerror(errno));
            return -1;
        }
        if (r == 0) {
            log_msg("req_read_all: peer closed off=%zu", off);
            return -1;
        }
        off += (size_t)r;
    }
    log_msg("req_read_all: done=%zu", off);
    return 0;
}

static int read_request(int fd, Request *req) {
    memset(req, 0, sizeof(*req));
    req->fd = fd;
    log_msg("read_request: begin fd=%d", fd);

    size_t cap = 8192;
    unsigned char *buf = malloc(cap);
    if (!buf) return -1;
    size_t len = 0;

    size_t header_end = 0;
    while (!header_end) {
        if (len == cap) {
            if (cap > 1024 * 1024) { free(buf); return -1; }
            cap *= 2;
            unsigned char *nb = realloc(buf, cap);
            if (!nb) { free(buf); return -1; }
            buf = nb;
        }
        ssize_t r = recv(fd, buf + len, cap - len, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            log_msg("read_request: header recv error errno=%d (%s)", errno, strerror(errno));
            free(buf);
            return -1;
        }
        if (r == 0) {
            log_msg("read_request: header peer closed");
            free(buf);
            return -1;
        }
        len += (size_t)r;
        for (size_t i = 3; i < len; i++) {
            if (buf[i-3]=='\r' && buf[i-2]=='\n' && buf[i-1]=='\r' && buf[i]=='\n') {
                header_end = i + 1;
                break;
            }
        }
    }

    char *headers = strndup((char *)buf, header_end);
    if (!headers) {
        log_msg("read_request: OOM for headers");
        free(buf);
        return -1;
    }

    char *save = NULL;
    char *line = strtok_r(headers, "\r\n", &save);
    if (!line) {
        log_msg("read_request: empty request line");
        free(headers);
        free(buf);
        return -1;
    }

    char url[4096] = {0};
    if (sscanf(line, "%7s %4095s", req->method, url) != 2) {
        log_msg("read_request: bad request line '%s'", line);
        free(headers); free(buf); return -1;
    }
    char *q = strchr(url, '?');
    if (q) {
        *q = 0;
        snprintf(req->query, sizeof(req->query), "%s", q + 1);
    }
    snprintf(req->path, sizeof(req->path), "%s", url);

    req->content_length = 0;
    req->content_type[0] = 0;

    while ((line = strtok_r(NULL, "\r\n", &save)) != NULL) {
        if (strncasecmp(line, "Content-Length:", 15) == 0) {
            const char *v = line + 15;
            while (*v && isspace((unsigned char)*v)) v++;
            req->content_length = (size_t)strtoull(v, NULL, 10);
        } else if (strncasecmp(line, "Content-Type:", 13) == 0) {
            const char *v = line + 13;
            while (*v && isspace((unsigned char)*v)) v++;
            snprintf(req->content_type, sizeof(req->content_type), "%s", v);
        }
    }

    size_t have_body = len - header_end;
    log_msg("read_request: method=%s path=%s content_length=%zu have_body=%zu ctype=%s",
            req->method, req->path, req->content_length, have_body, req->content_type);
    if (req->content_length > 64 * 1024 * 1024) {
        log_msg("read_request: payload too large");
        free(headers); free(buf);
        return -2;
    }

    if (req->content_length > 0) {
        req->body = malloc(req->content_length + 1);
        if (!req->body) { free(headers); free(buf); return -1; }

        size_t copy = have_body;
        if (copy > req->content_length) copy = req->content_length;
        memcpy(req->body, buf + header_end, copy);
        if (copy < req->content_length) {
            if (req_read_all(fd, req->body + copy, req->content_length - copy) != 0) {
                log_msg("read_request: body read failed copy=%zu need=%zu", copy, req->content_length);
                free(headers); free(buf); free(req->body); req->body = NULL;
                return -1;
            }
        }
        req->body[req->content_length] = 0;
    }

    free(headers);
    free(buf);
    log_msg("read_request: done method=%s path=%s", req->method, req->path);
    return 0;
}

static void free_request(Request *req) {
    free(req->body);
    req->body = NULL;
}

static char *query_param(const Request *req, const char *name) {
    KVList q;
    if (parse_urlencoded(req->query, &q) != 0) return NULL;
    const char *v = kvl_get(&q, name);
    char *o = v ? strdup(v) : NULL;
    kvl_free(&q);
    return o;
}

static int parse_body_form(const Request *req, KVList *kv) {
    if (strncasecmp(req->content_type, "application/x-www-form-urlencoded", 33) != 0) {
        kvl_init(kv);
        return 0;
    }
    return parse_urlencoded((char *)req->body, kv);
}

static int parse_stamps(char ***out, size_t *out_len) {
    *out = NULL;
    *out_len = 0;
    if (!g_cfg.stamps_csv || !*g_cfg.stamps_csv) return 0;
    char *tmp = strdup(g_cfg.stamps_csv);
    if (!tmp) return -1;
    size_t cap = 8;
    char **arr = malloc(cap * sizeof(char *));
    if (!arr) { free(tmp); return -1; }

    char *save = NULL;
    char *tok = strtok_r(tmp, ",", &save);
    while (tok) {
        char *t = trim_dup(tok);
        if (t && *t) {
            if (*out_len == cap) {
                cap *= 2;
                char **na = realloc(arr, cap * sizeof(char *));
                if (!na) { free(t); goto fail; }
                arr = na;
            }
            arr[*out_len] = t;
            (*out_len)++;
        } else {
            free(t);
        }
        tok = strtok_r(NULL, ",", &save);
    }
    free(tmp);
    *out = arr;
    return 0;
fail:
    for (size_t i = 0; i < *out_len; i++) free(arr[i]);
    free(arr);
    free(tmp);
    return -1;
}

static void free_stamps(char **s, size_t n) {
    for (size_t i = 0; i < n; i++) free(s[i]);
    free(s);
}

static int cmp_strp(const void *a, const void *b) {
    const char *const *sa = a;
    const char *const *sb = b;
    return strcmp(*sa, *sb);
}

static void split_sort_tags(const char *tags, char ***out, size_t *out_len) {
    *out = NULL;
    *out_len = 0;
    if (!tags || !*tags) return;
    char *tmp = strdup(tags);
    if (!tmp) return;
    size_t cap = 8;
    char **arr = malloc(cap * sizeof(char *));
    if (!arr) { free(tmp); return; }
    char *save = NULL;
    char *tok = strtok_r(tmp, " \t\r\n", &save);
    while (tok) {
        if (*out_len == cap) {
            cap *= 2;
            char **na = realloc(arr, cap * sizeof(char *));
            if (!na) break;
            arr = na;
        }
        arr[*out_len] = strdup(tok);
        if (!arr[*out_len]) break;
        (*out_len)++;
        tok = strtok_r(NULL, " \t\r\n", &save);
    }
    qsort(arr, *out_len, sizeof(char *), cmp_strp);
    *out = arr;
    free(tmp);
}

static void free_str_array(char **arr, size_t n) {
    for (size_t i = 0; i < n; i++) free(arr[i]);
    free(arr);
}

static char *build_docs_html(const DocList *docs) {
    char **stamps = NULL;
    size_t stamps_n = 0;
    parse_stamps(&stamps, &stamps_n);

    char *buf = NULL;
    size_t len = 0, cap = 0;

    for (size_t i = 0; i < docs->len; i++) {
        const Doc *d = &docs->items[i];
        char *t = html_escape(d->title);
        sb_appendf(&buf, &len, &cap,
            "<div class='col' data-doc-id='%lld'><div class='card shadow-sm'>"
            "<a href='/file/%s'><img src='/file/%s.jpg' width='100%%' style='max-height:280px;object-fit:contain;background:#fff'></a>"
            "<div class='card-body'><p class='card-text'>%s</p>"
            "<div class='d-flex justify-content-between align-items-center'><div class='btn-group'>"
            "<a class='btn btn-sm btn-outline-secondary' href='/file/%s' target='_blank'>Open</a>"
            "<button class='btn btn-sm btn-outline-secondary' onclick='MyDelete(%lld,this)'>Delete</button>"
            "</div><small><span class='doc-date' data-id='%lld' style='cursor:pointer'></span></small></div>"
            "<div class='mt-2' data-tag-container><div class='d-flex flex-wrap gap-1 align-items-center'>",
            d->id, t ? t : "", t ? t : "", t ? t : "", t ? t : "", d->id, d->id);

        char **tagarr = NULL;
        size_t tagcnt = 0;
        split_sort_tags(d->tags, &tagarr, &tagcnt);
        for (size_t ti = 0; ti < tagcnt; ti++) {
            char *te = html_escape(tagarr[ti]);
            sb_appendf(&buf, &len, &cap,
                "<span class='tag-badge'><span onclick=\"searchTag('%s')\" style='cursor:pointer'>%s</span>"
                "<button class='tag-remove' onclick=\"removeTag('%lld','%s',this);event.stopPropagation();\">&#215;</button></span>",
                te ? te : "", te ? te : "", d->id, te ? te : "");
            free(te);
        }
        free_str_array(tagarr, tagcnt);

        for (size_t si = 0; si < stamps_n; si++) {
            char *se = html_escape(stamps[si]);
            sb_appendf(&buf, &len, &cap,
                "<button class='tag-stamp' data-stamp-tag='%s' onclick=\"applyStamp('%lld','%s',this)\">%s</button>",
                se ? se : "", d->id, se ? se : "", se ? se : "");
            free(se);
        }
        sb_appendf(&buf, &len, &cap,
            "<input type='text' class='tag-add-input' placeholder='+ tag' style='display:none' data-tag-input>"
            "<button class='tag-badge' onclick='showTagInput(this)' data-tag-add-btn>+</button>"
            "</div><div><button class='btn btn-link btn-sm p-0 mt-1' onclick=\"toggleHistory('%lld',this);return false;\">history</button>"
            "<div class='small text-muted mt-1' style='display:none' data-history-panel></div></div></div></div></div></div>",
            d->id);
        free(t);
    }

    free_stamps(stamps, stamps_n);
    if (!buf) return strdup("");
    return buf;
}

static void render_index(Response *resp, const char *q, const char *search_label, long long cnt, const DocList *docs) {
    KVList vars;
    kvl_init(&vars);

    char *q_esc = html_escape(q ? q : "");
    char *sl_esc = html_escape(search_label ? search_label : "");
    char count_buf[64];
    snprintf(count_buf, sizeof(count_buf), "%lld", cnt);
    char *docs_html = build_docs_html(docs);

    kvl_add(&vars, "QUERY", q_esc ? q_esc : "");
    kvl_add(&vars, "SEARCH_LABEL", sl_esc ? sl_esc : "");
    kvl_add(&vars, "RESULT_COUNT", count_buf);
    kvl_add(&vars, "DOCS_HTML", docs_html ? docs_html : "");

    if (render_template("index.html", &vars, resp) != 0) {
        response_set_text(resp, 500, "text/plain; charset=utf-8", "Template render failed: views/index.html");
    }

    free(q_esc);
    free(sl_esc);
    free(docs_html);
    kvl_free(&vars);
}

static void handle_index(const Request *req, Response *resp) {
    char err[512] = {0};
    char *search = query_param(req, "search");
    DocList docs;
    long long cnt = 0;
    if (fetch_docs(search, &docs, &cnt, err, sizeof(err)) != 0) {
        char msg[1024];
        snprintf(msg, sizeof(msg), "DB error: %s", err);
        response_set_text(resp, 500, "text/plain; charset=utf-8", msg);
        free(search);
        return;
    }
    char label[256];
    if (search && *search) snprintf(label, sizeof(label), "%s", search);
    else snprintf(label, sizeof(label), "Last %d", g_cfg.overview_limit);
    render_index(resp, search ? search : "", label, cnt, &docs);
    doclist_free(&docs);
    free(search);
}

static void handle_upload_get(Response *resp) {
    KVList vars;
    kvl_init(&vars);
    if (render_template("upload.html", &vars, resp) != 0) {
        response_set_text(resp, 500, "text/plain; charset=utf-8", "Template render failed: views/upload.html");
    }
    kvl_free(&vars);
}

static int extract_boundary(const char *ct, char *out, size_t outn) {
    const char *p = strstr(ct, "boundary=");
    if (!p) return -1;
    p += 9;
    if (*p == '"') {
        p++;
        const char *e = strchr(p, '"');
        if (!e) return -1;
        size_t n = (size_t)(e - p);
        if (n + 1 > outn) return -1;
        memcpy(out, p, n);
        out[n] = 0;
        return 0;
    }
    size_t n = strcspn(p, ";\r\n");
    if (n + 1 > outn) return -1;
    memcpy(out, p, n);
    out[n] = 0;
    return 0;
}

static int bytes_find(const unsigned char *hay, size_t hlen, const unsigned char *needle, size_t nlen) {
    if (nlen == 0 || hlen < nlen) return -1;
    for (size_t i = 0; i + nlen <= hlen; i++) {
        if (memcmp(hay + i, needle, nlen) == 0) return (int)i;
    }
    return -1;
}

static int run_cmd_capture(const char *cmd, char **out) {
    *out = NULL;
    FILE *p = popen(cmd, "r");
    if (!p) return -1;
    char *buf = NULL;
    size_t len = 0, cap = 0;
    char tmp[4096];
    while (fgets(tmp, sizeof(tmp), p)) {
        size_t n = strlen(tmp);
        if (len + n + 1 > cap) {
            size_t nc = cap ? cap * 2 : 8192;
            while (len + n + 1 > nc) nc *= 2;
            char *nb = realloc(buf, nc);
            if (!nb) { free(buf); pclose(p); return -1; }
            buf = nb;
            cap = nc;
        }
        memcpy(buf + len, tmp, n);
        len += n;
    }
    int rc = pclose(p);
    if (!buf) buf = strdup("");
    else buf[len] = 0;
    *out = buf;
    return rc;
}

static void sanitize_single_quotes(char *s) {
    for (; *s; s++) if (*s == '\'') *s = ' ';
}

static void get_upload_rel_dir(char *out, size_t outn) {
    time_t t = time(NULL);
    struct tm tmv;
    localtime_r(&t, &tmv);
    snprintf(out, outn, "data/files/%04d/%02d/", tmv.tm_year + 1900, tmv.tm_mon + 1);
}

static char *basename_dup(const char *s) {
    const char *p = strrchr(s, '/');
    const char *q = strrchr(s, '\\');
    const char *b = s;
    if (p && (!q || p > q)) b = p + 1;
    else if (q) b = q + 1;
    return strdup(b);
}

static int parse_multipart_and_save(const Request *req, char **saved_rel, char *err, size_t err_len) {
    *saved_rel = NULL;
    char boundary[256];
    if (extract_boundary(req->content_type, boundary, sizeof(boundary)) != 0) {
        snprintf(err, err_len, "missing multipart boundary");
        return -1;
    }

    char marker[300];
    snprintf(marker, sizeof(marker), "--%s", boundary);
    size_t mlen = strlen(marker);

    const unsigned char *body = req->body;
    size_t blen = req->content_length;

    int start = bytes_find(body, blen, (unsigned char *)marker, mlen);
    if (start < 0) {
        snprintf(err, err_len, "multipart start not found");
        return -1;
    }
    size_t pos = (size_t)start + mlen;
    if (pos + 2 <= blen && body[pos] == '\r' && body[pos + 1] == '\n') pos += 2;

    int h_end_rel = bytes_find(body + pos, blen - pos, (unsigned char *)"\r\n\r\n", 4);
    if (h_end_rel < 0) {
        snprintf(err, err_len, "multipart headers malformed");
        return -1;
    }
    size_t h_end = pos + (size_t)h_end_rel;
    char *h = strndup((char *)body + pos, h_end - pos);
    if (!h) {
        snprintf(err, err_len, "OOM");
        return -1;
    }

    char *fn = NULL;
    char *cd = strcasestr(h, "Content-Disposition:");
    if (cd) {
        char *fnp = strcasestr(cd, "filename=");
        if (fnp) {
            fnp += 9;
            if (*fnp == '"') {
                fnp++;
                char *e = strchr(fnp, '"');
                if (e) fn = strndup(fnp, (size_t)(e - fnp));
            } else {
                size_t n = strcspn(fnp, ";\r\n");
                fn = strndup(fnp, n);
            }
        }
    }
    free(h);

    if (!fn || !*fn) {
        free(fn);
        snprintf(err, err_len, "no filename in multipart");
        return -1;
    }
    char *base = basename_dup(fn);
    free(fn);
    if (!base || !*base) {
        free(base);
        snprintf(err, err_len, "invalid filename");
        return -1;
    }

    size_t data_start = h_end + 4;
    char end_marker[304];
    snprintf(end_marker, sizeof(end_marker), "\r\n--%s", boundary);
    int d_end_rel = bytes_find(body + data_start, blen - data_start, (unsigned char *)end_marker, strlen(end_marker));
    if (d_end_rel < 0) {
        free(base);
        snprintf(err, err_len, "multipart body malformed");
        return -1;
    }
    size_t data_len = (size_t)d_end_rel;

    char rel_dir[64];
    get_upload_rel_dir(rel_dir, sizeof(rel_dir));
    char *dir_abs = path_join2(g_cfg.home, rel_dir);
    if (!dir_abs) {
        free(base);
        snprintf(err, err_len, "OOM");
        return -1;
    }
    if (ensure_dir(dir_abs) != 0) {
        free(base);
        free(dir_abs);
        snprintf(err, err_len, "cannot create upload dir");
        return -1;
    }

    size_t reln = strlen(rel_dir) + strlen(base) + 1;
    char *rel = malloc(reln);
    if (!rel) {
        free(base);
        free(dir_abs);
        snprintf(err, err_len, "OOM");
        return -1;
    }
    snprintf(rel, reln, "%s%s", rel_dir, base);

    char *abs = path_join2(g_cfg.home, rel);
    if (!abs) {
        free(base); free(dir_abs); free(rel);
        snprintf(err, err_len, "OOM");
        return -1;
    }

    FILE *f = fopen(abs, "wb");
    if (!f) {
        free(base); free(dir_abs); free(rel); free(abs);
        snprintf(err, err_len, "cannot open output file");
        return -1;
    }
    if (data_len && fwrite(body + data_start, 1, data_len, f) != data_len) {
        fclose(f);
        unlink(abs);
        free(base); free(dir_abs); free(rel); free(abs);
        snprintf(err, err_len, "failed writing uploaded file");
        return -1;
    }
    fclose(f);

    *saved_rel = rel;
    free(base);
    free(dir_abs);
    free(abs);
    return 0;
}

static int append_date_header_txt(const char *txtpath, const char *new_date) {
    unsigned char *buf = NULL;
    size_t len = 0;
    if (read_file_all(txtpath, &buf, &len) != 0) return 0;
    char *txt = (char *)buf;
    char *stripped = strip_eldoar_date_header(txt);
    free(buf);
    if (!stripped) return -1;
    size_t outn = strlen(stripped) + strlen(new_date) + 32;
    char *out = malloc(outn);
    if (!out) {
        free(stripped);
        return -1;
    }
    snprintf(out, outn, "ELDOAR-DATE: %s\n%s", new_date, stripped);
    int rc = write_file_all(txtpath, out, strlen(out));
    free(stripped);
    free(out);
    return rc;
}

static char *load_doc_content_from_txt_by_title(const char *title) {
    char *txtpath = path_join3(g_cfg.home, title, ".txt");
    if (!txtpath) return strdup("");
    unsigned char *buf = NULL;
    size_t len = 0;
    if (read_file_all(txtpath, &buf, &len) != 0) {
        log_msg("load_doc_content_from_txt_by_title: read failed path=%s errno=%d (%s)", txtpath, errno, strerror(errno));
        free(txtpath);
        return strdup("");
    }
    log_msg("load_doc_content_from_txt_by_title: read ok path=%s len=%zu", txtpath, len);
    free(txtpath);
    char *out = malloc(len + 1);
    if (!out) {
        free(buf);
        return strdup("");
    }
    memcpy(out, buf, len);
    out[len] = 0;
    free(buf);
    return out;
}

static void handle_upload_post(const Request *req, Response *resp) {
    if (strncasecmp(req->content_type, "multipart/form-data", 19) != 0) {
        response_set_text(resp, 400, "text/plain; charset=utf-8", "Expected multipart/form-data");
        return;
    }

    char err[512] = {0};
    char *rel = NULL;
    if (parse_multipart_and_save(req, &rel, err, sizeof(err)) != 0) {
        char msg[768];
        snprintf(msg, sizeof(msg), "Upload parse failed: %s", err);
        response_set_text(resp, 400, "text/plain; charset=utf-8", msg);
        return;
    }

    char *abs = path_join2(g_cfg.home, rel);
    char *txtp = path_join3(g_cfg.home, rel, ".txt");
    char *jpgp = path_join3(g_cfg.home, rel, ".jpg");
    if (!abs || !txtp || !jpgp) {
        free(rel); free(abs); free(txtp); free(jpgp);
        response_set_text(resp, 500, "text/plain; charset=utf-8", "OOM");
        return;
    }

    char *esc_abs = mw_escape_sql_literal(abs);
    if (!esc_abs) {
        free(rel); free(abs); free(txtp); free(jpgp);
        response_set_text(resp, 500, "text/plain; charset=utf-8", "OOM");
        return;
    }

    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "pdf2txt '%s'", esc_abs);
    char *content = NULL;
    run_cmd_capture(cmd, &content);
    if (!content) content = strdup("");
    sanitize_single_quotes(content);

    if (strlen(content) < 10) {
        char cmd2[4096];
        snprintf(cmd2, sizeof(cmd2), "ocrmypdf -l deu -dc '%s' '%s' >/dev/null 2>&1", esc_abs, esc_abs);
        system(cmd2);
        free(content);
        content = NULL;
        run_cmd_capture(cmd, &content);
        if (!content) content = strdup("");
        sanitize_single_quotes(content);
    }

    write_file_all(txtp, content, strlen(content));

    long long id = now_ms();
    if (insert_doc_row(id, rel, content, "", err, sizeof(err)) != 0) {
        free(rel); free(abs); free(txtp); free(jpgp); free(esc_abs); free(content);
        char msg[768];
        snprintf(msg, sizeof(msg), "Insert failed: %s", err);
        response_set_text(resp, 500, "text/plain; charset=utf-8", msg);
        return;
    }

    char cmd3[4096];
    snprintf(cmd3, sizeof(cmd3), "convert -background white -alpha remove -alpha off '%s[0]' '%s' >/dev/null 2>&1", esc_abs, jpgp);
    system(cmd3);

    free(esc_abs);
    free(rel);
    free(abs);
    free(txtp);
    free(jpgp);
    free(content);

    response_set_text(resp, 302, "text/plain; charset=utf-8", "Redirect");
}

static void handle_admin_get(Response *resp) {
    char err[512] = {0};
    long long c = 0;
    if (count_docs(&c, err, sizeof(err)) != 0) {
        char msg[768];
        snprintf(msg, sizeof(msg), "DB error: %s", err);
        response_set_text(resp, 500, "text/plain; charset=utf-8", msg);
        return;
    }
    KVList vars;
    kvl_init(&vars);
    char cbuf[64];
    snprintf(cbuf, sizeof(cbuf), "%lld", c);
    kvl_add(&vars, "DOC_COUNT", cbuf);
    if (render_template("admin.html", &vars, resp) != 0) {
        response_set_text(resp, 500, "text/plain; charset=utf-8", "Template render failed: views/admin.html");
    }
    kvl_free(&vars);
}

static void handle_admin_reindex(Response *resp) {
    char cmd[PATH_MAX + 64];
    snprintf(cmd, sizeof(cmd), "cd '%s' && perl reindex.pl >/tmp/postarchiv-reindex.log 2>&1", g_cfg.home);
    system(cmd);
    response_set_text(resp, 302, "text/plain; charset=utf-8", "Redirect");
}

static void handle_file_tags_get(long long id, Response *resp) {
    char err[512] = {0};
    char *title = NULL;
    int rc = fetch_doc_title_by_id(id, &title, err, sizeof(err));
    if (rc == 1) {
        response_set_text(resp, 404, "text/plain; charset=utf-8", "Not found");
        return;
    }
    if (rc != 0) {
        char msg[768];
        snprintf(msg, sizeof(msg), "DB error: %s", err);
        response_set_text(resp, 500, "text/plain; charset=utf-8", msg);
        return;
    }

    char *pdf_path = path_join2(g_cfg.home, title);
    free(title);
    if (!pdf_path) {
        response_set_text(resp, 500, "text/plain; charset=utf-8", "OOM");
        return;
    }
    TagList tl;
    read_tags_file(pdf_path, &tl);
    free(pdf_path);

    char *json = tags_to_json(&tl);
    taglist_free(&tl);
    if (!json) {
        response_set_text(resp, 500, "text/plain; charset=utf-8", "OOM");
        return;
    }
    response_set_text(resp, 200, "application/json; charset=utf-8", json);
    free(json);
}

static void handle_file_tag_adddel(long long id, const Request *req, Response *resp, int add_mode) {
    log_msg("tag_route: begin id=%lld mode=%s", id, add_mode ? "add" : "remove");
    KVList form;
    if (parse_body_form(req, &form) != 0) {
        log_msg("tag_route: parse_body_form failed");
        response_set_text(resp, 400, "text/plain; charset=utf-8", "Bad form body");
        return;
    }
    const char *tagv = kvl_get(&form, "tag");
    char *tag = tagv ? trim_dup(tagv) : NULL;
    kvl_free(&form);
    if (!tag || !*tag || contains_ws(tag)) {
        log_msg("tag_route: invalid tag input");
        free(tag);
        response_set_text(resp, 400, "text/plain; charset=utf-8", "Invalid tag");
        return;
    }
    log_msg("tag_route: tag='%s'", tag);

    char err[512] = {0};
    char *title = NULL;
    int frc = fetch_doc_title_by_id(id, &title, err, sizeof(err));
    if (frc == 1) {
        log_msg("tag_route: doc not found id=%lld", id);
        free(tag);
        response_set_text(resp, 404, "text/plain; charset=utf-8", "Not found");
        return;
    }
    if (frc != 0) {
        log_msg("tag_route: fetch_doc_title_by_id failed err=%s", err);
        free(tag);
        char msg[768];
        snprintf(msg, sizeof(msg), "DB error: %s", err);
        response_set_text(resp, 500, "text/plain; charset=utf-8", msg);
        return;
    }
    log_msg("tag_route: title='%s'", title);

    char *pdf_path = path_join2(g_cfg.home, title);
    if (!pdf_path) {
        log_msg("tag_route: path_join2 OOM");
        free(tag); free(title);
        response_set_text(resp, 500, "text/plain; charset=utf-8", "OOM");
        return;
    }
    log_msg("tag_route: pdf_path='%s'", pdf_path);

    TagList tl;
    if (read_tags_file(pdf_path, &tl) != 0) {
        log_msg("tag_route: read_tags_file failed path=%s", pdf_path);
        free(tag); free(title); free(pdf_path);
        response_set_text(resp, 500, "text/plain; charset=utf-8", "Failed reading tags file");
        return;
    }
    log_msg("tag_route: current_tags=%zu", tl.len);

    if (add_mode) {
        int exists = 0;
        for (size_t i = 0; i < tl.len; i++) {
            if (!tl.items[i].has_removed && strcmp(tl.items[i].tag, tag) == 0) {
                exists = 1;
                break;
            }
        }
        if (!exists && taglist_add(&tl, tag, now_s(), 0, 0) != 0) {
            log_msg("tag_route: taglist_add failed");
            free(tag); free(title); free(pdf_path); taglist_free(&tl);
            response_set_text(resp, 500, "text/plain; charset=utf-8", "Out of memory adding tag");
            return;
        }
    } else {
        long long n = now_s();
        for (size_t i = 0; i < tl.len; i++) {
            if (!tl.items[i].has_removed && strcmp(tl.items[i].tag, tag) == 0) {
                tl.items[i].has_removed = 1;
                tl.items[i].removed = n;
            }
        }
    }

    if (write_tags_file(pdf_path, &tl) != 0) {
        log_msg("tag_route: write_tags_file failed path=%s errno=%d (%s)", pdf_path, errno, strerror(errno));
        free(tag); free(title); free(pdf_path); taglist_free(&tl);
        response_set_text(resp, 500, "text/plain; charset=utf-8", "Failed writing tags file (permissions/path?)");
        return;
    }
    log_msg("tag_route: write_tags_file ok");
    free(pdf_path);

    char *active = active_tags_str(&tl);
    if (!active) active = strdup("");
    log_msg("tag_route: active_tags='%s'", active ? active : "");

    char *content = load_doc_content_from_txt_by_title(title);
    if (!content) content = strdup("");
    if (!content) {
        log_msg("tag_route: content load OOM");
        free(tag); free(title); free(active); taglist_free(&tl);
        response_set_text(resp, 500, "text/plain; charset=utf-8", "OOM");
        return;
    }
    log_msg("tag_route: content_len=%zu", strlen(content));

    if (delete_doc_row(id, err, sizeof(err)) != 0 || insert_doc_row(id, title, content, active, err, sizeof(err)) != 0) {
        log_msg("tag_route: db update failed err=%s", err);
        free(tag); free(title); free(content); free(active); taglist_free(&tl);
        char msg[768];
        snprintf(msg, sizeof(msg), "DB update failed: %s", err);
        response_set_text(resp, 500, "text/plain; charset=utf-8", msg);
        return;
    }
    log_msg("tag_route: db update ok");

    if (add_mode) {
        char *je = json_escape(active);
        char out[2048];
        snprintf(out, sizeof(out), "{\"ok\":1,\"tags\":\"%s\"}", je ? je : "");
        free(je);
        response_set_text(resp, 200, "application/json; charset=utf-8", out);
    } else {
        response_set_text(resp, 200, "application/json; charset=utf-8", "{\"ok\":1}");
    }

    free(tag);
    free(title);
    free(content);
    free(active);
    taglist_free(&tl);
    log_msg("tag_route: done id=%lld", id);
}

static void handle_file_delete(long long id, Response *resp) {
    char err[512] = {0};
    char *title = NULL;
    int rc = fetch_doc_title_by_id(id, &title, err, sizeof(err));
    if (rc == 1) {
        response_set_text(resp, 404, "text/plain; charset=utf-8", "Not found");
        return;
    }
    if (rc != 0) {
        char msg[768];
        snprintf(msg, sizeof(msg), "DB error: %s", err);
        response_set_text(resp, 500, "text/plain; charset=utf-8", msg);
        return;
    }

    if (delete_doc_row(id, err, sizeof(err)) != 0) {
        free(title);
        char msg[768];
        snprintf(msg, sizeof(msg), "Delete failed: %s", err);
        response_set_text(resp, 500, "text/plain; charset=utf-8", msg);
        return;
    }

    char *pdf = path_join2(g_cfg.home, title);
    char *jpg = path_join3(g_cfg.home, title, ".jpg");
    char *txt = path_join3(g_cfg.home, title, ".txt");
    char *tagf = path_join3(g_cfg.home, title, ".tags");

    const char *arr[4] = {pdf, jpg, txt, tagf};
    for (int i = 0; i < 4; i++) {
        if (!arr[i]) continue;
        struct stat st;
        if (stat(arr[i], &st) == 0 && S_ISREG(st.st_mode)) {
            char *dst = malloc(strlen(arr[i]) + 9);
            if (!dst) continue;
            sprintf(dst, "%s.deleted", arr[i]);
            rename(arr[i], dst);
            free(dst);
        }
    }

    free(pdf); free(jpg); free(txt); free(tagf); free(title);
    response_set_text(resp, 200, "application/json; charset=utf-8", "{\"ok\":1}");
}

static void handle_file_put_date(long long old_id, const Request *req, Response *resp) {
    KVList form;
    if (parse_body_form(req, &form) != 0) {
        response_set_text(resp, 400, "text/plain; charset=utf-8", "Bad form body");
        return;
    }
    const char *d = kvl_get(&form, "date");
    char *date_str = d ? strdup(d) : NULL;
    int y = 0, m = 0, day = 0;
    if (!date_str || sscanf(date_str, "%4d-%2d-%2d", &y, &m, &day) != 3) {
        free(date_str);
        kvl_free(&form);
        response_set_text(resp, 400, "text/plain; charset=utf-8", "Invalid date");
        return;
    }
    kvl_free(&form);

    char err[512] = {0};
    char *title = NULL, *tags = NULL;
    int rc = fetch_doc_title_tags_by_id(old_id, &title, &tags, err, sizeof(err));
    if (rc == 1) {
        response_set_text(resp, 404, "text/plain; charset=utf-8", "Not found");
        return;
    }
    if (rc != 0) {
        char msg[768];
        snprintf(msg, sizeof(msg), "DB error: %s", err);
        response_set_text(resp, 500, "text/plain; charset=utf-8", msg);
        return;
    }

    char *txtpath = path_join3(g_cfg.home, title, ".txt");
    if (txtpath) {
        append_date_header_txt(txtpath, date_str);
        free(txtpath);
    }

    long long new_id = 0;
    if (find_free_id_for_date(y, m, day, &new_id, err, sizeof(err)) != 0) {
        free(title); free(tags);
        free(date_str);
        char msg[768];
        snprintf(msg, sizeof(msg), "ID selection failed: %s", err);
        response_set_text(resp, 500, "text/plain; charset=utf-8", msg);
        return;
    }

    char *from_txt = load_doc_content_from_txt_by_title(title);
    if (!from_txt) from_txt = strdup("");
    char *clean_content = strip_eldoar_date_header(from_txt ? from_txt : "");
    if (!clean_content) clean_content = strdup(from_txt ? from_txt : "");
    free(from_txt);

    if (delete_doc_row(old_id, err, sizeof(err)) != 0 || insert_doc_row(new_id, title, clean_content, tags, err, sizeof(err)) != 0) {
        free(title); free(tags); free(clean_content);
        free(date_str);
        char msg[768];
        snprintf(msg, sizeof(msg), "Update failed: %s", err);
        response_set_text(resp, 500, "text/plain; charset=utf-8", msg);
        return;
    }

    char out[128];
    snprintf(out, sizeof(out), "{\"new_id\":\"%lld\"}", new_id);
    response_set_text(resp, 200, "application/json; charset=utf-8", out);

    free(title); free(tags); free(clean_content);
    free(date_str);
}

static void handle_static_file(const char *rel, Response *resp) {
    if (!path_is_safe_rel(rel)) {
        response_set_text(resp, 404, "text/plain; charset=utf-8", "Not found");
        return;
    }
    char *path = path_join2(g_cfg.home, rel);
    if (!path) {
        response_set_text(resp, 500, "text/plain; charset=utf-8", "OOM");
        return;
    }
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        free(path);
        response_set_text(resp, 404, "text/plain; charset=utf-8", "Not found");
        return;
    }

    unsigned char *blob = NULL;
    size_t len = 0;
    if (read_file_all(path, &blob, &len) != 0) {
        free(path);
        response_set_text(resp, 500, "text/plain; charset=utf-8", "Read error");
        return;
    }

    response_set_blob(resp, 200, guess_ctype(path), blob, len);
    free(blob);
    free(path);
}

static void handle_file_download(const char *rest, Response *resp) {
    if (!path_is_safe_rel(rest)) {
        response_set_text(resp, 404, "text/plain; charset=utf-8", "Not found");
        return;
    }
    handle_static_file(rest, resp);
}

static void route_request(const Request *req, Response *resp, char *extra_headers, size_t extra_n) {
    extra_headers[0] = 0;

    if (strcmp(req->method, "GET") == 0 && strcmp(req->path, "/") == 0) {
        handle_index(req, resp);
        return;
    }
    if (strcmp(req->method, "GET") == 0 && strcmp(req->path, "/upload") == 0) {
        handle_upload_get(resp);
        return;
    }
    if (strcmp(req->method, "POST") == 0 && strcmp(req->path, "/upload") == 0) {
        handle_upload_post(req, resp);
        if (resp->status == 302) snprintf(extra_headers, extra_n, "Location: /\r\n");
        return;
    }
    if (strcmp(req->method, "GET") == 0 && strcmp(req->path, "/admin") == 0) {
        handle_admin_get(resp);
        return;
    }
    if (strcmp(req->method, "POST") == 0 && strcmp(req->path, "/admin/reindex") == 0) {
        handle_admin_reindex(resp);
        if (resp->status == 302) snprintf(extra_headers, extra_n, "Location: /admin\r\n");
        return;
    }

    if (strcmp(req->method, "GET") == 0 && (strncmp(req->path, "/css/", 5) == 0 || strncmp(req->path, "/js/", 4) == 0)) {
        char rel[PATH_MAX];
        snprintf(rel, sizeof(rel), "public%s", req->path);
        handle_static_file(rel, resp);
        return;
    }

    if (strncmp(req->path, "/file/", 6) == 0) {
        const char *p = req->path + 6;

        long long id = -1;
        char suffix[64] = {0};
        if (sscanf(p, "%lld/%63s", &id, suffix) >= 1 && id >= 0) {
            char exact[128];
            snprintf(exact, sizeof(exact), "%lld", id);
            if (strcmp(p, exact) == 0) {
                if (strcmp(req->method, "DELETE") == 0) {
                    handle_file_delete(id, resp);
                    return;
                }
                if (strcmp(req->method, "PUT") == 0) {
                    handle_file_put_date(id, req, resp);
                    return;
                }
            }
            char tags_path[128];
            snprintf(tags_path, sizeof(tags_path), "%lld/tags", id);
            if (strcmp(p, tags_path) == 0 && strcmp(req->method, "GET") == 0) {
                handle_file_tags_get(id, resp);
                return;
            }
            char tag_path[128];
            snprintf(tag_path, sizeof(tag_path), "%lld/tag", id);
            if (strcmp(p, tag_path) == 0 && strcmp(req->method, "POST") == 0) {
                handle_file_tag_adddel(id, req, resp, 1);
                return;
            }
            if (strcmp(p, tag_path) == 0 && strcmp(req->method, "DELETE") == 0) {
                handle_file_tag_adddel(id, req, resp, 0);
                return;
            }
        }

        if (strcmp(req->method, "GET") == 0) {
            handle_file_download(p, resp);
            return;
        }
    }

    response_set_text(resp, 404, "text/plain; charset=utf-8", "Not found");
}

static int create_listener(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (strcmp(host, "0.0.0.0") == 0) addr.sin_addr.s_addr = INADDR_ANY;
    else if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        close(fd);
        return -1;
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, 64) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);

    g_cfg.sphinx_host = envs("SPHINX_HOST", "127.0.0.1");
    g_cfg.sphinx_port = (uint16_t)envi("SPHINX_PORT", 9306);
    g_cfg.home = envs("ELDOAR_HOME", "/app");
    g_cfg.template_dir = envs("TEMPLATE_DIR", "./views");
    g_cfg.overview_limit = envi("OVERVIEW_LIMIT", 18);
    g_cfg.overview_order = envs("OVERVIEW_ORDER", "DESC");
    g_cfg.stamps_csv = envs("ELDOAR_STAMPS", "");
    g_cfg.listen_port = envi("PORT", 3000);
    g_cfg.listen_host = envs("HOST", "0.0.0.0");
    g_cfg.db_user = envs("DB_USER", "");
    g_cfg.db_password = envs("DB_PASSWORD", "");
    g_cfg.db_name = envs("DB_NAME", "");
    g_debug = envi("DEBUG", 1);

    int lfd = create_listener(g_cfg.listen_host, g_cfg.listen_port);
    if (lfd < 0) die("failed to listen on %s:%d", g_cfg.listen_host, g_cfg.listen_port);

    fprintf(stderr, "postarchiv-c listening on %s:%d (home=%s sphinx=%s:%u)\n",
            g_cfg.listen_host, g_cfg.listen_port, g_cfg.home, g_cfg.sphinx_host, (unsigned)g_cfg.sphinx_port);

    for (;;) {
        struct sockaddr_in cli;
        socklen_t cl = sizeof(cli);
        int cfd = accept(lfd, (struct sockaddr *)&cli, &cl);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            log_msg("accept failed errno=%d (%s)", errno, strerror(errno));
            continue;
        }
        log_msg("accept ok fd=%d", cfd);

        struct timeval tv;
        tv.tv_sec = 20;
        tv.tv_usec = 0;
        setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        Request req;
        Response resp;
        response_init(&resp);

        int rr = read_request(cfd, &req);
        if (rr == -2) {
            log_msg("request rejected: payload too large");
            response_set_text(&resp, 413, "text/plain; charset=utf-8", "Payload too large");
            send_response(cfd, &resp, NULL);
            free(resp.body);
            close(cfd);
            continue;
        }
        if (rr != 0) {
            log_msg("request rejected: bad request/read timeout");
            response_set_text(&resp, 400, "text/plain; charset=utf-8", "Bad request");
            send_response(cfd, &resp, NULL);
            free(resp.body);
            close(cfd);
            continue;
        }

        char extra[256];
        log_msg("request: %s %s", req.method, req.path);
        route_request(&req, &resp, extra, sizeof(extra));
        send_response(cfd, &resp, extra[0] ? extra : NULL);

        free(resp.body);
        free_request(&req);
        close(cfd);
    }

    return 0;
}
