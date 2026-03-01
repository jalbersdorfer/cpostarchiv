# Minimal MySQL Wire Client (No External C Dependencies)

This implements only the subset needed for your app:

- TCP connect
- MySQL protocol handshake/auth (`mysql_native_password`)
- `COM_QUERY`
- parse `OK`, `ERR`, and text result sets

## Build

```bash
make
```

## Quick Probe

```bash
./mysql_probe 127.0.0.1 9306 "" "" "SELECT * FROM testrt ORDER BY id DESC LIMIT 3"
```

For standard MySQL (if needed):

```bash
./mysql_probe 127.0.0.1 3306 root secret "SELECT 1" mysql
```

## API

- `mw_connect(...)`
- `mw_query(...)`
- `mw_result_free(...)`
- `mw_close(...)`
- `mw_escape_sql_literal(...)`

Header: `mysql_wire.h`  
Implementation: `mysql_wire.c`
