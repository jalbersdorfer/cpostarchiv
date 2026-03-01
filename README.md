# postarchiv-c

Dependency-free C rewrite of the Perl Dancer app, using an in-project minimal MySQL wire client (no MySQL library).

Includes:

- HTTP server and route handlers for search/upload/file/tag/admin flows
- minimal MySQL protocol implementation (`mysql_native_password`, `COM_QUERY`, text result sets)
- file/tag logic compatible with `.tags` JSON files

## KSP / Ops Profile

- Single primary executable: `postarchiv` (`75,144` bytes in current x86_64 build; ~`74K`)
- Helper executable: `mysql_probe` (`25,840` bytes; ~`26K`)
- Minimal runtime link set: `libc` + Linux loader only (`ldd postarchiv`)
- No third-party C libraries and no MySQL client library dependency
- Batteries included in-tree:
  - MySQL wire protocol client (`mysql_wire.*`)
  - Template engine (`template_engine.*`)
  - HTTP server and routing in `app.c`
- No language runtime needed (no Perl/Python/Node runtime for the server process)
- Build output is a single deployable server binary (`./postarchiv`) plus editable `views/*.html`

## Runtime Dependencies

The C server is dependency-light, but feature-complete operation still relies on external tools/services:

- Manticore/Sphinx SQL endpoint (`SPHINX_HOST`/`SPHINX_PORT`)
- `pdf2txt` for text extraction
- `ocrmypdf` as OCR fallback for low-text PDFs
- ImageMagick `convert` for `.jpg` preview generation
- `perl reindex.pl` for admin-triggered reindex

## RAM Notes

- Core server process itself is lightweight (small binary, blocking single-process model).
- Real memory pressure is dominated by external subprocesses (`ocrmypdf`, `convert`, `pdf2txt`) during uploads/reprocessing.
- Practical sizing:
  - For serving/search/tagging only: low-memory environments are fine.
  - For OCR-heavy uploads: provision significantly more RAM headroom for worker tools.

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
