# FDAP specification

The FDAP server owns a list of applications and tokens, and which paths within the JSON they can access.

Clients (applications) make http requests to the server with a token in an `Authorization: Bearer` header. By default clients read the token from the `FDAP_TOKEN` environment variable.

The requests follow the format: `https://fdap_server/SEG1/SEG2/.../SEGN` where the `SEG` path segments are the path in the JSON (successive map keys from the configuration root). By default the fdap server base url is in the `FDAP_BASE_URL` environment variable and may include path segments to preceed the `SEG` above if the server is colocated in an HTTP server at a subpath.

- `GET` returns the JSON subtree at the specified path

- `POST` replaces the JSON subtree at the specified path

- `DELETE` deletes the JSON subtree at the specified path

## Server behavior

This directory contains conformant server behavior test cases defined by [`conformance.schema.json`](../source/generated/jsonschema/conformance.schema.json).

- [`read.json`](./read.json), [`write.json`](./write.json) and [`delete.json`](./delete.json) - the methods above
- [`paths.json`](./paths.json) - how path segments are encoded
- [`auth.json`](./auth.json) - requests with missing or unknown tokens

1. Start a server with the case's `setup`:

   - `tokens` are tokens with read and write access to the whole tree.
   - `db` is the initial database (`null` if absent).
   - Ignore `openfdap`, which only appears in `openfdap`'s own test cases.

2. Run each step in order against that server, keeping variables captured in one step for later steps:

   - Build the URL path. If `path` is an array of segments, percent-encode each one (every byte other than ASCII letters, digits and `-._~`; the whole segments `.` and `..` become `%2E` and `%2E%2E`), then join them with `/` behind a leading `/`. If `path` is a string, use it exactly as given.
   - Send `token` as `Authorization: Bearer TOKEN`, along with `headers`. Replace `{{name}}` in header values with the captured variable `name`.
   - Send `body` as JSON, or `raw_body` exactly as given.
   - Check only the fields present in `expect`: `status`; `body` (the response parsed as JSON); `raw_body` (the exact response text); `headers`; and `db` (the full database contents after the request).
   - Save the response headers listed in `capture` as variables.

There's a [reference runner](../source/openfdap/tests/conformance.rs) that checks `openfdap` against these cases and its own in [`source/openfdap/tests/cases`](../source/openfdap/tests/cases). Run it with `cargo test -p openfdap --test conformance` in `source/`.
