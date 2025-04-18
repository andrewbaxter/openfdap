# What is FDAP

## Short

FDAP is a simple alternative to LDAP based around a single JSON tree and HTTP API.

## Longer

When deploying multiple server software they'll often have duplicate configuration that's unique to the deployment environment. Namely, user accounts, and configuration properties of those user accounts.

So an SSO gateway would read user accounts for authentication details, various servers would read user accounts for access details, or user details (email, profile picture), etc.

Rather than have each application maintain it's own per-user configuration or database that needs to be synced, you'd put all this information in the user directory (LDAP).

FDAP (Featherweight Directory Access Protocol) is an iteration on the directory concept aiming to simplify and use common data interchange formats.

# The protocol

The FDAP server maintains a list of applications and tokens, and which paths within the JSON they can access.

Clients (applications) make http requests to the server with a token in an `Authorization: Bearer` header. By default the token is in the `FDAP_TOKEN` environment variable.

The requests follow the format: `https://fdap_server/SEG1/SEG2/.../SEGN` where the `SEG` path segments are the path in the JSON (successive map keys or array indexes from the configuration root). By default the fdap server base url is in the `FDAP_BASE_URL` environment variable and may include path segments to preceed the `SEG` above if the server is colocated in an HTTP server at a subpath.

- `GET` returns the JSON subtree at the specified path

- `POST` replaces the JSON subtree at the specified path

- `DELETE` deletes the JSON subtree at the specified path

# What's in this repository

There's two things:

- `openfdap` - a simple reference implementation of an FDAP server

  [Documentation](./source/openfdap/readme.md)

- `fdap` - a Rust library for accessing an FDAP server

  [Documentation](./source/fdap/readme.md)

# Standard ontology

- `"user"` - record, each key corresponds to a user ID

  - `USER_ID`

    - `"name"` - The user's name in its canonical representation
