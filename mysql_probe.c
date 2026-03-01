#include "mysql_wire.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *argv0) {
    fprintf(stderr, "Usage: %s <host> <port> <user> <password> <sql> [database]\n", argv0);
}

int main(int argc, char **argv) {
    if (argc < 6 || argc > 7) {
        usage(argv[0]);
        return 2;
    }

    const char *host = argv[1];
    uint16_t port = (uint16_t)strtoul(argv[2], NULL, 10);
    const char *user = argv[3];
    const char *password = argv[4];
    const char *sql = argv[5];
    const char *database = (argc == 7) ? argv[6] : "";

    char err[512];
    mw_conn conn;
    if (mw_connect(&conn, host, port, user, password, database, err, sizeof(err)) != 0) {
        fprintf(stderr, "connect failed: %s\n", err);
        return 1;
    }

    mw_result r;
    if (mw_query(&conn, sql, &r, err, sizeof(err)) != 0) {
        fprintf(stderr, "query failed: %s\n", err);
        mw_close(&conn);
        return 1;
    }

    if (r.num_columns == 0) {
        printf("OK affected_rows=%llu insert_id=%llu\n",
               (unsigned long long)r.affected_rows,
               (unsigned long long)r.insert_id);
    } else {
        for (size_t c = 0; c < r.num_columns; c++) {
            printf("%s%s", r.columns[c] ? r.columns[c] : "", (c + 1 < r.num_columns) ? "\t" : "\n");
        }
        for (size_t i = 0; i < r.num_rows; i++) {
            for (size_t c = 0; c < r.num_columns; c++) {
                printf("%s%s", r.rows[i][c] ? r.rows[i][c] : "NULL", (c + 1 < r.num_columns) ? "\t" : "\n");
            }
        }
        printf("rows=%zu\n", r.num_rows);
    }

    mw_result_free(&r);
    mw_close(&conn);
    return 0;
}
