#define _POSIX_C_SOURCE 200112L
#include "mysql_wire.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define MW_CLIENT_LONG_PASSWORD 0x00000001u
#define MW_CLIENT_LONG_FLAG 0x00000004u
#define MW_CLIENT_CONNECT_WITH_DB 0x00000008u
#define MW_CLIENT_PROTOCOL_41 0x00000200u
#define MW_CLIENT_TRANSACTIONS 0x00002000u
#define MW_CLIENT_SECURE_CONNECTION 0x00008000u
#define MW_CLIENT_MULTI_RESULTS 0x00020000u
#define MW_CLIENT_PLUGIN_AUTH 0x00080000u

#define MW_COM_QUERY 0x03u
#define MW_MAX_PACKET (16u * 1024u * 1024u - 1u)

typedef struct {
    uint32_t state[5];
    uint64_t total_len;
    uint8_t buf[64];
    size_t buf_len;
} sha1_ctx;

static void mw_set_err(char *err, size_t err_len, const char *msg) {
    if (!err || err_len == 0) return;
    snprintf(err, err_len, "%s", msg);
}

static void mw_set_syserr(char *err, size_t err_len, const char *prefix) {
    if (!err || err_len == 0) return;
    snprintf(err, err_len, "%s: %s", prefix, strerror(errno));
}

static uint32_t rol32(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}

static void sha1_init(sha1_ctx *ctx) {
    ctx->state[0] = 0x67452301u;
    ctx->state[1] = 0xEFCDAB89u;
    ctx->state[2] = 0x98BADCFEu;
    ctx->state[3] = 0x10325476u;
    ctx->state[4] = 0xC3D2E1F0u;
    ctx->total_len = 0;
    ctx->buf_len = 0;
}

static void sha1_transform(sha1_ctx *ctx, const uint8_t block[64]) {
    uint32_t w[80];
    for (size_t i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (size_t i = 16; i < 80; i++) {
        w[i] = rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];
    uint32_t e = ctx->state[4];

    for (size_t i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999u;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1u;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDCu;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6u;
        }
        uint32_t temp = rol32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rol32(b, 30);
        b = a;
        a = temp;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

static void sha1_update(sha1_ctx *ctx, const uint8_t *data, size_t len) {
    ctx->total_len += len;
    while (len > 0) {
        size_t take = 64 - ctx->buf_len;
        if (take > len) take = len;
        memcpy(ctx->buf + ctx->buf_len, data, take);
        ctx->buf_len += take;
        data += take;
        len -= take;
        if (ctx->buf_len == 64) {
            sha1_transform(ctx, ctx->buf);
            ctx->buf_len = 0;
        }
    }
}

static void sha1_final(sha1_ctx *ctx, uint8_t out[20]) {
    uint64_t bits = ctx->total_len * 8u;
    uint8_t pad = 0x80u;
    sha1_update(ctx, &pad, 1);
    uint8_t zero = 0;
    while (ctx->buf_len != 56) {
        sha1_update(ctx, &zero, 1);
    }
    uint8_t lenbuf[8];
    for (size_t i = 0; i < 8; i++) {
        lenbuf[7 - i] = (uint8_t)(bits >> (i * 8));
    }
    sha1_update(ctx, lenbuf, 8);

    for (size_t i = 0; i < 5; i++) {
        out[i * 4] = (uint8_t)(ctx->state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

static void sha1_sum(const uint8_t *data, size_t len, uint8_t out[20]) {
    sha1_ctx ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, data, len);
    sha1_final(&ctx, out);
}

static void mysql_native_password_scramble(
    const char *password,
    const uint8_t *salt,
    size_t salt_len,
    uint8_t out[20]
) {
    uint8_t s1[20], s2[20], s3[20], x[20];
    sha1_sum((const uint8_t *)password, strlen(password), s1);
    sha1_sum(s1, 20, s2);

    uint8_t *tmp = (uint8_t *)malloc(salt_len + 20);
    if (!tmp) {
        memset(out, 0, 20);
        return;
    }
    memcpy(tmp, salt, salt_len);
    memcpy(tmp + salt_len, s2, 20);
    sha1_sum(tmp, salt_len + 20, s3);
    free(tmp);
    for (size_t i = 0; i < 20; i++) x[i] = s3[i] ^ s1[i];
    memcpy(out, x, 20);
}

static int write_all(int fd, const uint8_t *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = send(fd, buf + off, n - off, 0);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (w == 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

static int read_all(int fd, uint8_t *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = recv(fd, buf + off, n - off, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return -1;
        off += (size_t)r;
    }
    return 0;
}

static int read_packet(mw_conn *c, uint8_t **payload, uint32_t *payload_len, char *err, size_t err_len) {
    uint8_t hdr[4];
    if (read_all(c->fd, hdr, 4) != 0) {
        mw_set_syserr(err, err_len, "read packet header failed");
        return -1;
    }
    uint32_t len = (uint32_t)hdr[0] | ((uint32_t)hdr[1] << 8) | ((uint32_t)hdr[2] << 16);
    uint8_t seq = hdr[3];
    if (seq != c->seq) {
        mw_set_err(err, err_len, "packet sequence mismatch");
        return -1;
    }
    c->seq++;

    uint8_t *buf = NULL;
    if (len > 0) {
        buf = (uint8_t *)malloc(len);
        if (!buf) {
            mw_set_err(err, err_len, "out of memory");
            return -1;
        }
        if (read_all(c->fd, buf, len) != 0) {
            free(buf);
            mw_set_syserr(err, err_len, "read packet payload failed");
            return -1;
        }
    }
    *payload = buf;
    *payload_len = len;
    return 0;
}

static int write_packet(mw_conn *c, const uint8_t *payload, uint32_t payload_len, char *err, size_t err_len) {
    if (payload_len > MW_MAX_PACKET) {
        mw_set_err(err, err_len, "payload too large");
        return -1;
    }
    uint8_t hdr[4];
    hdr[0] = (uint8_t)(payload_len & 0xff);
    hdr[1] = (uint8_t)((payload_len >> 8) & 0xff);
    hdr[2] = (uint8_t)((payload_len >> 16) & 0xff);
    hdr[3] = c->seq++;
    if (write_all(c->fd, hdr, 4) != 0) {
        mw_set_syserr(err, err_len, "write packet header failed");
        return -1;
    }
    if (payload_len > 0 && write_all(c->fd, payload, payload_len) != 0) {
        mw_set_syserr(err, err_len, "write packet payload failed");
        return -1;
    }
    return 0;
}

static int parse_lenenc_int(const uint8_t *p, size_t n, size_t *off, uint64_t *out) {
    if (*off >= n) return -1;
    uint8_t fb = p[*off];
    if (fb < 0xfb) {
        *out = fb;
        (*off)++;
        return 0;
    }
    if (fb == 0xfc) {
        if (*off + 3 > n) return -1;
        *out = (uint64_t)p[*off + 1] | ((uint64_t)p[*off + 2] << 8);
        *off += 3;
        return 0;
    }
    if (fb == 0xfd) {
        if (*off + 4 > n) return -1;
        *out = (uint64_t)p[*off + 1] | ((uint64_t)p[*off + 2] << 8) | ((uint64_t)p[*off + 3] << 16);
        *off += 4;
        return 0;
    }
    if (fb == 0xfe) {
        if (*off + 9 > n) return -1;
        uint64_t v = 0;
        for (size_t i = 0; i < 8; i++) v |= ((uint64_t)p[*off + 1 + i] << (8 * i));
        *out = v;
        *off += 9;
        return 0;
    }
    return -1;
}

static int parse_lenenc_str(const uint8_t *p, size_t n, size_t *off, const uint8_t **s, size_t *slen, int *is_null) {
    if (*off >= n) return -1;
    if (p[*off] == 0xfb) {
        *is_null = 1;
        (*off)++;
        *s = NULL;
        *slen = 0;
        return 0;
    }
    uint64_t len = 0;
    if (parse_lenenc_int(p, n, off, &len) != 0) return -1;
    if ((uint64_t)(n - *off) < len) return -1;
    *is_null = 0;
    *s = p + *off;
    *slen = (size_t)len;
    *off += (size_t)len;
    return 0;
}

static int packet_is_eof(const uint8_t *p, uint32_t len) {
    return (len < 9 && len > 0 && p[0] == 0xfe);
}

static int packet_is_ok(const uint8_t *p, uint32_t len) {
    (void)len;
    return len > 0 && p[0] == 0x00;
}

static int packet_is_err(const uint8_t *p, uint32_t len) {
    (void)len;
    return len > 0 && p[0] == 0xff;
}

static void free_partial_rows(char ***rows, size_t built_rows, size_t ncols) {
    for (size_t r = 0; r < built_rows; r++) {
        if (!rows[r]) continue;
        for (size_t c = 0; c < ncols; c++) free(rows[r][c]);
        free(rows[r]);
    }
    free(rows);
}

static int parse_err_packet(const uint8_t *p, uint32_t len, char *err, size_t err_len) {
    if (len < 3 || p[0] != 0xff) {
        mw_set_err(err, err_len, "invalid ERR packet");
        return -1;
    }
    uint16_t code = (uint16_t)p[1] | ((uint16_t)p[2] << 8);
    size_t msg_off = 3;
    if (len >= 9 && p[3] == '#') msg_off = 9;
    if (msg_off > len) msg_off = len;
    snprintf(err, err_len, "server error %u: %.*s", code, (int)(len - msg_off), (const char *)(p + msg_off));
    return -1;
}

static int connect_tcp(const char *host, uint16_t port, int *fd_out, char *err, size_t err_len) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_s[16];
    snprintf(port_s, sizeof(port_s), "%u", (unsigned)port);

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(host, port_s, &hints, &res);
    if (rc != 0) {
        mw_set_err(err, err_len, gai_strerror(rc));
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0) {
        mw_set_syserr(err, err_len, "connect failed");
        return -1;
    }
    *fd_out = fd;
    return 0;
}

static int parse_handshake(mw_conn *c, const uint8_t *p, uint32_t len, char *err, size_t err_len) {
    if (len == 0) {
        mw_set_err(err, err_len, "empty handshake");
        return -1;
    }
    if (p[0] == 0xff) return parse_err_packet(p, len, err, err_len);
    if (p[0] < 0x0a) {
        mw_set_err(err, err_len, "unsupported handshake protocol");
        return -1;
    }

    size_t off = 1;
    while (off < len && p[off] != 0) off++;
    if (off >= len) {
        mw_set_err(err, err_len, "bad handshake server version");
        return -1;
    }
    off++;
    if (off + 4 > len) {
        mw_set_err(err, err_len, "bad handshake conn id");
        return -1;
    }
    off += 4;
    if (off + 8 > len) {
        mw_set_err(err, err_len, "bad handshake salt1");
        return -1;
    }
    memcpy(c->salt, p + off, 8);
    c->salt_len = 8;
    off += 8;
    if (off + 1 > len) return -1;
    off += 1;
    if (off + 2 > len) return -1;
    uint16_t cap_lo = (uint16_t)p[off] | ((uint16_t)p[off + 1] << 8);
    off += 2;
    if (off >= len) {
        c->server_capabilities = cap_lo;
        snprintf(c->auth_plugin, sizeof(c->auth_plugin), "mysql_native_password");
        return 0;
    }
    off += 1; /* charset */
    if (off + 2 > len) return -1;
    off += 2; /* status */
    if (off + 2 > len) return -1;
    uint16_t cap_hi = (uint16_t)p[off] | ((uint16_t)p[off + 1] << 8);
    off += 2;
    c->server_capabilities = ((uint32_t)cap_hi << 16) | cap_lo;

    uint8_t auth_plugin_data_len = 0;
    if (c->server_capabilities & MW_CLIENT_PLUGIN_AUTH) {
        if (off >= len) return -1;
        auth_plugin_data_len = p[off];
        off++;
    } else {
        if (off >= len) return -1;
        off++;
    }
    if (off + 10 > len) return -1;
    off += 10;

    if (c->server_capabilities & MW_CLIENT_SECURE_CONNECTION) {
        size_t need = 13;
        if (auth_plugin_data_len > 8) need = (size_t)auth_plugin_data_len - 8;
        if (off + need > len) need = len - off;
        if (need > 0) {
            size_t can = sizeof(c->salt) - c->salt_len;
            if (need > can) need = can;
            memcpy(c->salt + c->salt_len, p + off, need);
            c->salt_len += need;
        }
        while (off < len && p[off] != 0) off++;
        if (off < len && p[off] == 0) off++;
    }

    if (c->server_capabilities & MW_CLIENT_PLUGIN_AUTH && off < len) {
        size_t st = off;
        while (off < len && p[off] != 0) off++;
        size_t n = off - st;
        if (n > 0) {
            if (n >= sizeof(c->auth_plugin)) n = sizeof(c->auth_plugin) - 1;
            memcpy(c->auth_plugin, p + st, n);
            c->auth_plugin[n] = 0;
        }
    }

    if (c->auth_plugin[0] == 0) {
        snprintf(c->auth_plugin, sizeof(c->auth_plugin), "mysql_native_password");
    }
    return 0;
}

static int send_handshake_response(
    mw_conn *c,
    const char *user,
    const char *password,
    const char *database,
    char *err,
    size_t err_len
) {
    uint32_t caps = MW_CLIENT_LONG_PASSWORD |
                    MW_CLIENT_LONG_FLAG |
                    MW_CLIENT_PROTOCOL_41 |
                    MW_CLIENT_TRANSACTIONS |
                    MW_CLIENT_SECURE_CONNECTION |
                    MW_CLIENT_MULTI_RESULTS;

    if (database && *database) caps |= MW_CLIENT_CONNECT_WITH_DB;
    if (c->server_capabilities & MW_CLIENT_PLUGIN_AUTH) caps |= MW_CLIENT_PLUGIN_AUTH;
    caps &= c->server_capabilities | MW_CLIENT_PLUGIN_AUTH | MW_CLIENT_PROTOCOL_41 | MW_CLIENT_SECURE_CONNECTION |
            MW_CLIENT_CONNECT_WITH_DB | MW_CLIENT_LONG_PASSWORD | MW_CLIENT_LONG_FLAG | MW_CLIENT_TRANSACTIONS |
            MW_CLIENT_MULTI_RESULTS;

    uint8_t token[20];
    size_t token_len = 0;
    if (password && *password) {
        if (strcmp(c->auth_plugin, "mysql_native_password") != 0) {
            mw_set_err(err, err_len, "unsupported auth plugin");
            return -1;
        }
        mysql_native_password_scramble(password, c->salt, c->salt_len, token);
        token_len = 20;
    }

    size_t user_len = strlen(user ? user : "");
    size_t db_len = (database && *database) ? strlen(database) : 0;
    size_t plugin_len = (caps & MW_CLIENT_PLUGIN_AUTH) ? strlen(c->auth_plugin) : 0;

    size_t payload_len = 4 + 4 + 1 + 23 + user_len + 1 + 1 + token_len;
    if (caps & MW_CLIENT_CONNECT_WITH_DB) payload_len += db_len + 1;
    if (caps & MW_CLIENT_PLUGIN_AUTH) payload_len += plugin_len + 1;

    uint8_t *payload = (uint8_t *)calloc(1, payload_len);
    if (!payload) {
        mw_set_err(err, err_len, "out of memory");
        return -1;
    }
    size_t off = 0;
    payload[off++] = (uint8_t)(caps & 0xff);
    payload[off++] = (uint8_t)((caps >> 8) & 0xff);
    payload[off++] = (uint8_t)((caps >> 16) & 0xff);
    payload[off++] = (uint8_t)((caps >> 24) & 0xff);
    payload[off++] = 0x00;
    payload[off++] = 0x00;
    payload[off++] = 0x00;
    payload[off++] = 0x01; /* max packet: 16MB */
    payload[off++] = 33;   /* utf8_general_ci */
    off += 23;

    memcpy(payload + off, user ? user : "", user_len);
    off += user_len;
    payload[off++] = 0;

    payload[off++] = (uint8_t)token_len;
    if (token_len > 0) {
        memcpy(payload + off, token, token_len);
        off += token_len;
    }

    if (caps & MW_CLIENT_CONNECT_WITH_DB) {
        memcpy(payload + off, database, db_len);
        off += db_len;
        payload[off++] = 0;
    }

    if (caps & MW_CLIENT_PLUGIN_AUTH) {
        memcpy(payload + off, c->auth_plugin, plugin_len);
        off += plugin_len;
        payload[off++] = 0;
    }

    if (off != payload_len) {
        free(payload);
        mw_set_err(err, err_len, "handshake response size mismatch");
        return -1;
    }

    if (write_packet(c, payload, (uint32_t)payload_len, err, err_len) != 0) {
        free(payload);
        return -1;
    }
    free(payload);
    return 0;
}

static int finish_auth(mw_conn *c, const char *password, char *err, size_t err_len) {
    uint8_t *p = NULL;
    uint32_t len = 0;
    if (read_packet(c, &p, &len, err, err_len) != 0) return -1;

    if (packet_is_ok(p, len)) {
        free(p);
        return 0;
    }
    if (packet_is_err(p, len)) {
        int rc = parse_err_packet(p, len, err, err_len);
        free(p);
        return rc;
    }

    if (len > 0 && p[0] == 0xfe) {
        const uint8_t *plugin = p + 1;
        size_t poff = 1;
        while (poff < len && p[poff] != 0) poff++;
        if (poff >= len) {
            free(p);
            mw_set_err(err, err_len, "bad auth switch packet");
            return -1;
        }
        size_t plugin_len = poff - 1;
        uint8_t salt[32];
        size_t salt_len = len - (poff + 1);
        if (salt_len > sizeof(salt)) salt_len = sizeof(salt);
        memcpy(salt, p + poff + 1, salt_len);

        if (!(plugin_len == strlen("mysql_native_password") &&
              memcmp(plugin, "mysql_native_password", plugin_len) == 0)) {
            free(p);
            mw_set_err(err, err_len, "unsupported auth switch plugin");
            return -1;
        }
        free(p);

        uint8_t token[20];
        uint32_t tlen = 0;
        if (password && *password) {
            mysql_native_password_scramble(password, salt, salt_len, token);
            tlen = 20;
        }
        if (write_packet(c, token, tlen, err, err_len) != 0) return -1;

        p = NULL;
        len = 0;
        if (read_packet(c, &p, &len, err, err_len) != 0) return -1;
        if (packet_is_ok(p, len)) {
            free(p);
            return 0;
        }
        if (packet_is_err(p, len)) {
            int rc = parse_err_packet(p, len, err, err_len);
            free(p);
            return rc;
        }
        free(p);
        mw_set_err(err, err_len, "unexpected auth completion packet");
        return -1;
    }

    free(p);
    mw_set_err(err, err_len, "unexpected auth packet");
    return -1;
}

int mw_connect(
    mw_conn *c,
    const char *host,
    uint16_t port,
    const char *user,
    const char *password,
    const char *database,
    char *err,
    size_t err_len
) {
    if (!c || !host || !user) {
        mw_set_err(err, err_len, "invalid connect args");
        return -1;
    }
    memset(c, 0, sizeof(*c));
    c->fd = -1;

    if (connect_tcp(host, port, &c->fd, err, err_len) != 0) return -1;

    c->seq = 0;
    uint8_t *p = NULL;
    uint32_t len = 0;
    if (read_packet(c, &p, &len, err, err_len) != 0) {
        mw_close(c);
        return -1;
    }
    if (parse_handshake(c, p, len, err, err_len) != 0) {
        free(p);
        mw_close(c);
        return -1;
    }
    free(p);

    c->seq = 1;
    if (send_handshake_response(c, user, password, database, err, err_len) != 0) {
        mw_close(c);
        return -1;
    }
    if (finish_auth(c, password, err, err_len) != 0) {
        mw_close(c);
        return -1;
    }
    return 0;
}

void mw_close(mw_conn *c) {
    if (!c) return;
    if (c->fd >= 0) close(c->fd);
    c->fd = -1;
    c->seq = 0;
}

static int parse_ok_packet(mw_result *out, const uint8_t *p, uint32_t len) {
    if (!out || len == 0 || p[0] != 0x00) return -1;
    size_t off = 1;
    uint64_t affected = 0, insert_id = 0;
    if (parse_lenenc_int(p, len, &off, &affected) != 0) return -1;
    if (parse_lenenc_int(p, len, &off, &insert_id) != 0) return -1;
    out->affected_rows = affected;
    out->insert_id = insert_id;
    return 0;
}

int mw_query(mw_conn *c, const char *sql, mw_result *out, char *err, size_t err_len) {
    if (!c || c->fd < 0 || !sql || !out) {
        mw_set_err(err, err_len, "invalid query args");
        return -1;
    }
    memset(out, 0, sizeof(*out));

    size_t slen = strlen(sql);
    uint8_t *cmd = (uint8_t *)malloc(1 + slen);
    if (!cmd) {
        mw_set_err(err, err_len, "out of memory");
        return -1;
    }
    cmd[0] = MW_COM_QUERY;
    memcpy(cmd + 1, sql, slen);

    c->seq = 0;
    if (write_packet(c, cmd, (uint32_t)(1 + slen), err, err_len) != 0) {
        free(cmd);
        return -1;
    }
    free(cmd);

    uint8_t *p = NULL;
    uint32_t len = 0;
    if (read_packet(c, &p, &len, err, err_len) != 0) return -1;

    if (packet_is_ok(p, len)) {
        int rc = parse_ok_packet(out, p, len);
        free(p);
        if (rc != 0) mw_set_err(err, err_len, "failed to parse OK packet");
        return rc;
    }
    if (packet_is_err(p, len)) {
        int rc = parse_err_packet(p, len, err, err_len);
        free(p);
        return rc;
    }

    size_t off = 0;
    uint64_t ncols64 = 0;
    if (parse_lenenc_int(p, len, &off, &ncols64) != 0 || ncols64 > SIZE_MAX) {
        free(p);
        mw_set_err(err, err_len, "invalid column count packet");
        return -1;
    }
    free(p);
    size_t ncols = (size_t)ncols64;
    out->num_columns = ncols;

    out->columns = (char **)calloc(ncols, sizeof(char *));
    if (!out->columns) {
        mw_set_err(err, err_len, "out of memory");
        return -1;
    }

    for (size_t i = 0; i < ncols; i++) {
        p = NULL;
        len = 0;
        if (read_packet(c, &p, &len, err, err_len) != 0) goto fail;
        if (packet_is_err(p, len)) {
            parse_err_packet(p, len, err, err_len);
            free(p);
            goto fail;
        }
        off = 0;
        const uint8_t *s = NULL;
        size_t sl = 0;
        int is_null = 0;
        for (int part = 0; part < 6; part++) {
            if (parse_lenenc_str(p, len, &off, &s, &sl, &is_null) != 0) {
                free(p);
                mw_set_err(err, err_len, "bad column definition");
                goto fail;
            }
            if (part == 4) {
                out->columns[i] = (char *)malloc(sl + 1);
                if (!out->columns[i]) {
                    free(p);
                    mw_set_err(err, err_len, "out of memory");
                    goto fail;
                }
                memcpy(out->columns[i], s, sl);
                out->columns[i][sl] = 0;
            }
        }
        free(p);
    }

    p = NULL;
    len = 0;
    if (read_packet(c, &p, &len, err, err_len) != 0) goto fail;
    if (!(packet_is_eof(p, len) || packet_is_ok(p, len))) {
        if (packet_is_err(p, len)) parse_err_packet(p, len, err, err_len);
        else mw_set_err(err, err_len, "missing column terminator");
        free(p);
        goto fail;
    }
    free(p);

    char ***rows = NULL;
    size_t rows_cap = 0;
    size_t rows_len = 0;
    while (1) {
        p = NULL;
        len = 0;
        if (read_packet(c, &p, &len, err, err_len) != 0) goto fail_rows;
        if (packet_is_eof(p, len) || packet_is_ok(p, len)) {
            free(p);
            break;
        }
        if (packet_is_err(p, len)) {
            parse_err_packet(p, len, err, err_len);
            free(p);
            goto fail_rows;
        }

        if (rows_len == rows_cap) {
            size_t new_cap = rows_cap ? rows_cap * 2 : 16;
            char ***nr = (char ***)realloc(rows, new_cap * sizeof(char **));
            if (!nr) {
                free(p);
                mw_set_err(err, err_len, "out of memory");
                goto fail_rows;
            }
            rows = nr;
            rows_cap = new_cap;
        }

        char **row = (char **)calloc(ncols, sizeof(char *));
        if (!row) {
            free(p);
            mw_set_err(err, err_len, "out of memory");
            goto fail_rows;
        }
        off = 0;
        for (size_t cidx = 0; cidx < ncols; cidx++) {
            const uint8_t *s = NULL;
            size_t sl = 0;
            int is_null = 0;
            if (parse_lenenc_str(p, len, &off, &s, &sl, &is_null) != 0) {
                free(p);
                for (size_t k = 0; k < ncols; k++) free(row[k]);
                free(row);
                mw_set_err(err, err_len, "bad row packet");
                goto fail_rows;
            }
            if (is_null) {
                row[cidx] = NULL;
            } else {
                row[cidx] = (char *)malloc(sl + 1);
                if (!row[cidx]) {
                    free(p);
                    for (size_t k = 0; k < ncols; k++) free(row[k]);
                    free(row);
                    mw_set_err(err, err_len, "out of memory");
                    goto fail_rows;
                }
                memcpy(row[cidx], s, sl);
                row[cidx][sl] = 0;
            }
        }
        free(p);
        rows[rows_len++] = row;
    }

    out->rows = rows;
    out->num_rows = rows_len;
    return 0;

fail_rows:
    free_partial_rows(rows, rows_len, ncols);
fail:
    mw_result_free(out);
    return -1;
}

void mw_result_free(mw_result *r) {
    if (!r) return;
    if (r->rows) {
        for (size_t i = 0; i < r->num_rows; i++) {
            if (!r->rows[i]) continue;
            for (size_t j = 0; j < r->num_columns; j++) free(r->rows[i][j]);
            free(r->rows[i]);
        }
        free(r->rows);
    }
    if (r->columns) {
        for (size_t i = 0; i < r->num_columns; i++) free(r->columns[i]);
        free(r->columns);
    }
    memset(r, 0, sizeof(*r));
}

char *mw_escape_sql_literal(const char *s) {
    if (!s) {
        char *z = (char *)malloc(1);
        if (z) z[0] = 0;
        return z;
    }
    size_t n = strlen(s);
    size_t cap = n * 2 + 1;
    char *out = (char *)malloc(cap);
    if (!out) return NULL;
    size_t j = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)s[i];
        switch (ch) {
            case 0:
                out[j++] = '\\';
                out[j++] = '0';
                break;
            case '\n':
                out[j++] = '\\';
                out[j++] = 'n';
                break;
            case '\r':
                out[j++] = '\\';
                out[j++] = 'r';
                break;
            case '\\':
                out[j++] = '\\';
                out[j++] = '\\';
                break;
            case '\'':
                out[j++] = '\\';
                out[j++] = '\'';
                break;
            case '"':
                out[j++] = '\\';
                out[j++] = '"';
                break;
            case 0x1a:
                out[j++] = '\\';
                out[j++] = 'Z';
                break;
            default:
                out[j++] = (char)ch;
                break;
        }
    }
    out[j] = 0;
    return out;
}
