#include "template_engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int read_file_all(const char *path, char **out) {
    *out = NULL;
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
    char *buf = malloc((size_t)n + 1);
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
    return 0;
}

static char *replace_all(const char *src, const char *needle, const char *repl) {
    if (!src || !needle || !*needle || !repl) return NULL;
    size_t srcn = strlen(src), nn = strlen(needle), rn = strlen(repl);
    size_t cnt = 0;
    for (const char *p = src; (p = strstr(p, needle)); p += nn) cnt++;
    size_t outn = srcn + cnt * (rn - nn) + 1;
    char *out = malloc(outn);
    if (!out) return NULL;
    size_t oi = 0;
    const char *cur = src;
    while (1) {
        const char *p = strstr(cur, needle);
        if (!p) break;
        size_t seg = (size_t)(p - cur);
        memcpy(out + oi, cur, seg);
        oi += seg;
        memcpy(out + oi, repl, rn);
        oi += rn;
        cur = p + nn;
    }
    strcpy(out + oi, cur);
    return out;
}

char *tpl_render_file(
    const char *dir,
    const char *name,
    const char **keys,
    const char **values,
    size_t nvars,
    char *err,
    size_t err_len
) {
    if (!dir || !name) {
        if (err && err_len) snprintf(err, err_len, "invalid template args");
        return NULL;
    }

    size_t pathn = strlen(dir) + strlen(name) + 2;
    char *path = malloc(pathn);
    if (!path) {
        if (err && err_len) snprintf(err, err_len, "OOM");
        return NULL;
    }
    snprintf(path, pathn, "%s/%s", dir, name);

    char *raw = NULL;
    if (read_file_all(path, &raw) != 0) {
        if (err && err_len) snprintf(err, err_len, "failed reading template: %s", path);
        free(path);
        return NULL;
    }
    free(path);

    char *cur = raw;
    char *owned = NULL;
    for (size_t i = 0; i < nvars; i++) {
        if (!keys[i]) continue;
        char key[256];
        if (snprintf(key, sizeof(key), "{{%s}}", keys[i]) >= (int)sizeof(key)) continue;
        const char *val = values && values[i] ? values[i] : "";
        char *next = replace_all(cur, key, val);
        if (!next) {
            if (owned) free(owned);
            else free(raw);
            if (err && err_len) snprintf(err, err_len, "OOM");
            return NULL;
        }
        if (owned) free(owned);
        else free(raw);
        owned = next;
        cur = owned;
    }

    if (!owned) return raw;
    return owned;
}
