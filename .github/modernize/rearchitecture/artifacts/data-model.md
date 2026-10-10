# Data Model

The bundled target application persists a single SQLite entity:

- `todos` (`target_app/app.py:22-28`): `id INTEGER PRIMARY KEY AUTOINCREMENT`, `title TEXT NOT NULL`, and `completed BOOLEAN NOT NULL` constrained to `0` or `1`, default `0`.

There are no declared relationships or ORM mappings in the target app. Flask request context stores the SQLite connection in `g`; each request commits writes and the teardown handler closes the connection. Blue Agent memory and metrics use their own runtime repositories/models, but the source inspected here exposes no shared persistent relation to the target application's `todos` table.
