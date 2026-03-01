# postarchiv-c

Dependency-free C rewrite of the Perl Dancer app, using an in-project minimal MySQL wire client (no MySQL library).

Includes:

- HTTP server and route handlers for search/upload/file/tag/admin flows
- minimal MySQL protocol implementation (`mysql_native_password`, `COM_QUERY`, text result sets)
- file/tag logic compatible with `.tags` JSON files

## Build

```bash
make
```

## Run Server

```bash
HOST=0.0.0.0 \
PORT=3000 \
ELDOAR_HOME=/path/to/postarchiv \
SPHINX_HOST=127.0.0.1 \
SPHINX_PORT=9306 \
OVERVIEW_LIMIT=18 \
OVERVIEW_ORDER=DESC \
ELDOAR_STAMPS="todo,done" \
TEMPLATE_DIR=./views \
./postarchiv
```

Then open `http://127.0.0.1:3000/`.

## Implemented Routes

- `GET /`
- `GET /upload`
- `POST /upload`
- `GET /file/**`
- `DELETE /file/:id`
- `PUT /file/:id`
- `GET /file/:id/tags`
- `POST /file/:id/tag`
- `DELETE /file/:id/tag`
- `GET /admin`
- `POST /admin/reindex`
- `GET /css/*`, `GET /js/*` from `$ELDOAR_HOME/public`

## Templates

HTML is file-based and loaded from `TEMPLATE_DIR` (default `./views`):

- `views/index.html`
- `views/upload.html`
- `views/admin.html`
- `views/_doc_card.html`
- `views/_tag_badge.html`
- `views/_stamp_button.html`

Template engine implementation is isolated from the app server:

- `template_engine.h`
- `template_engine.c`

Template placeholders use `{{NAME}}`:

- `index.html`: `{{QUERY}}`, `{{RESULT_COUNT}}`, `{{SEARCH_LABEL}}`, `{{DOCS_HTML}}`
- `_doc_card.html`: `{{DOC_ID}}`, `{{TITLE}}`, `{{TAG_BADGES}}`, `{{STAMP_BUTTONS}}`
- `_tag_badge.html`: `{{DOC_ID}}`, `{{TAG}}`
- `_stamp_button.html`: `{{DOC_ID}}`, `{{STAMP}}`
- `admin.html`: `{{DOC_COUNT}}`

## MySQL Probe (standalone)

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
