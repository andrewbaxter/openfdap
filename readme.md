# What is FDAP

FDAP is a protocol for centrally managing configs for applications, as a single JSON tree, with a simple JSON HTTP API. It's in the same space as LDAP.

Why have applications get their config from FDAP instead of using local config files?

- It allows you to have mutable configs for applications on immutable systems

- Share configs for multiple instances; modify configs in one place to have it apply everywhere

- Centralize configs for users for multiple applications: you only need to remove users in one place

- One thing to backup - the FDAP server database

I made this because wanted something simple for the above reasons, and I didn't want to write code LDAP-protocol code, I didn't want to set up/manage an LDAP server, and I didn't need all of LDAP's features.

FDAP stands for (Featherweight Directory Access Protocol).

# What's in this repository

- The protocol pseudo-specification (here)

- `openfdap` - a simple reference implementation of an FDAP server

  [Documentation](./source/openfdap/readme.md)

- `fdap` - a Rust library for accessing an FDAP server

  [Documentation](./source/fdap/readme.md)

# The protocol

The FDAP server maintains a list of applications and tokens, and which paths within the JSON they can access.

Clients (applications) make http requests to the server with a token in an `Authorization: Bearer` header. By default clients read the token from the `FDAP_TOKEN` environment variable.

The requests follow the format: `https://fdap_server/SEG1/SEG2/.../SEGN` where the `SEG` path segments are the path in the JSON (successive map keys or array indexes from the configuration root). By default the fdap server base url is in the `FDAP_BASE_URL` environment variable and may include path segments to preceed the `SEG` above if the server is colocated in an HTTP server at a subpath.

- `GET` returns the JSON subtree at the specified path

- `POST` replaces the JSON subtree at the specified path

- `DELETE` deletes the JSON subtree at the specified path

# How can I use this today?

- [`fdap-login`](https://github.com/andrewbaxter/fdap-login/) - This is a minimal identity provider reads users from FDAP. It currently supports 3-leg OIDC.

- [`sunwet`](https://github.com/andrewbaxter/sunwet/) - This is an experimental knowledge-graph-based personal-knowledge and file server which can be configured to read config and users from FDAP.

# Standard ontology

- `"user"` - record, each key corresponds to a user ID
  - `USER_ID`
    - `"name"` - The user's name in its canonical representation
