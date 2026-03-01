#ifndef MYSQL_WIRE_H
#define MYSQL_WIRE_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    size_t num_columns;
    char **columns;
    size_t num_rows;
    char ***rows;
    uint64_t affected_rows;
    uint64_t insert_id;
} mw_result;

typedef struct {
    int fd;
    uint8_t seq;
    uint32_t server_capabilities;
    char auth_plugin[64];
    uint8_t salt[32];
    size_t salt_len;
} mw_conn;

int mw_connect(
    mw_conn *c,
    const char *host,
    uint16_t port,
    const char *user,
    const char *password,
    const char *database,
    char *err,
    size_t err_len
);

void mw_close(mw_conn *c);

int mw_query(mw_conn *c, const char *sql, mw_result *out, char *err, size_t err_len);

void mw_result_free(mw_result *r);

char *mw_escape_sql_literal(const char *s);

#endif
