# AGENTS.md

This repository contains the dependency-free C rewrite of `postarchiv`.

## Scope

- Main server: `app.c`
- MySQL wire client: `mysql_wire.c`, `mysql_wire.h`
- Template engine: `template_engine.c`, `template_engine.h`
- HTML templates: `views/*.html`

## Build and Run

- Build: `make postarchiv`
- Run (example):
  - `HOST=0.0.0.0 PORT=3003 ELDOAR_HOME=/path/to/postarchiv SPHINX_HOST=127.0.0.1 SPHINX_PORT=9306 TEMPLATE_DIR=./views ./postarchiv`

## Template Rules

- Keep HTML in `views/*.html`.
- Do not inline HTML markup in `app.c` unless there is no practical alternative.
- Placeholder format is `{{NAME}}`.

## Caching

- Static `.css`, `.js`, and `/file/*.pdf.jpg` responses should keep cache headers enabled.

## Logging and Debug

- Enable request/route diagnostics with `DEBUG=1`.
- Keep logs concise and actionable for route failures (especially tag/date routes).

## Data Safety

- Never delete or modify the `data` folder in this repository.
- `data/` may be a symlink to external content and must be treated as persistent user data.

## Change Discipline

- Prefer small, targeted patches.
- Preserve current route behavior unless explicitly asked to change it.
- If behavior changes, update `README.md` in the same change.
