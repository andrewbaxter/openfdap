This is a fully functional and minimal FDAP server.

At the moment it stores the config as a single file on disk updated with atomic writes.

You can back it up live without worrying about consistency.

# Installation + setup

Install it with: `cargo build`

Run it with `openfdap serve --config CONFIG_FILE`, or with the config JSON in the `OPENFDAP_CONFIG` environment variable. `openfdap serve --config CONFIG_FILE --validate` checks the config and exits.

It requires a configuration file like:

```json
{
  "bind_addr": "127.0.0.1:17778",
  "data_dir": "/var/fdap",
  "max_write_bytes": 1048576,
  "users": [
    {
      "token": {"sha256":"c8aa3b22a00d9c859e71e2c6d30f0fe036987300aa5f6e71466f1dce2585a3ef"},
      "access": [{ "path": [], "action": { "read": true, "write": true } }]
    },
    {
      "token": {"sha256":"2234e2ef41a94876a75efb62873059331c71df03c162058ec3b63f130bea99e1"},
      "access": [
        {
          "path": [{ "string": "user" }, "wildcard", { "string": "email" }],
          "action": { "read": true, "write": false }
        },
        {
          "path": [{ "string": "user" }, "wildcard", { "string": "app1_data" }],
          "action": { "read": true, "write": true }
        }
      ]
    }
  ]
}
```

- `bind_addr` is the address the server listens on.

- `data_dir` is the directory in which the database (`db.json`) is stored, and can/should be backed up.

- `users` is a list of applications, each with a `token` and `access` rules.

  `token` is `{ "sha256": "HEX" }`; generate it with `echo -n MY_TOKEN | openfdap hash-token`.

  Each rule has a `path` made up of `string` and `wildcard` segments that's matched against the path of a request, and an `action` with the allowed actions at that path. When several rules match, the longest (most specific) wins, and among equal-length rules a literal segment beats a wildcard.

  You can also add application entries to an identical `fdap_user` tree at the root of the database, to manage fdap access dynamically. Config-defined access has priority over database-defined access.

# Setting the config

Your config can have any format, but see the top readme for standard fields.

Create your config file, `fdap.json`.

Commit it with `curl -X POST https://my-fdap-server/ --header 'Authorization: Bearer ROOT_TOKEN' --data @fdap.json`.

Note that this will replace all data at `/`. If you have different processes managing FDAP state you'll need to do more piecewise updates to individual subpaths.

# OpenFDAP ontology

- `"fdap_user"` - list of applications, same format as the `users` field in the openfdap config (optional)

  This is merged with the config `users`, allowing you to configure new applications while running. Entries with invalid token hashes are logged and ignored.

# Avoiding data errors

Applications may provide JSON schema for their FDAP configs. You can combine them into a single schema like:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "$schema": {
      "type": "string"
    },
    "sunwet": {
      "$schema": "https://andrewbaxter.github.io/sunwet/jsonschema/fdap.schema.json"
    },
    "user": {
      "type": "object",
      "additionalProperties": {
        "type": "object",
        "additionalProperties": false,
        "properties": {
          "fdap-oidc": {
            "$schema": "https://andrewbaxter.github.io/fdap-oidc/jsonschema/fdap_user.schema.json"
          },
          "sunwet": {
            "$schema": "https://andrewbaxter.github.io/sunwet/jsonschema/fdap_user.schema.json"
          }
        }
      }
    }
  }
}
```

Save it as `fdap.schema.json`.

If you modify your config like:

```json
{
  "$schema": "file://./fdap.schema.json",
  ...
}
```

editors (VS Code) will show you config errors while you edit.
