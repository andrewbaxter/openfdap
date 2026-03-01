This is a fully functional and minimal FDAP server.

At the moment it stores the config as a single file on disk updated with atomic writes.

You can back it up live without worrying about consistency.

# Installation + setup

Install it with: `cargo build`

It requires a configuration file like:

```json
{
  "bind_addr": "127.0.0.1:17778",
  "data_dir": "/var/fdap/database.json",
  "users": {
    "ROOT_TOKEN": [[[], { "read": true, "write": true }]],
    "APP1_TOKEN": [
      [
        [{ "string": "user" }, "wildcard", { "string": "email" }],
        {
          "read": true,
          "write": false
        }
      ],
      [
        [{ "string": "user" }, "wildcard", { "string": "app1_data" }],
        {
          "read": true,
          "write": true
        }
      ]
    ]
  }
}
```

- `bind_addr` is the address the server listens on

- `data_dir` is the dir in which the config is stored, and can/should be backed up

- `users` is a mapping of application tokens to application access rules.

  Each rule is a pair, with the first element being a path made up of `string` and `wildcard` segments that's matched against the path of a request, and the second element being the allowed actions at that path.

  You can also add application entries to an identical `fdap_user` tree at the root of the database, to manage fdap access dynamically. Config-defined access has priority over database-defined access.

# Setting the config

Your config can have any format, but see the top readme for standard fields.

Create your config file, `fdap.json`.

Commit it with `curl -X POST https://my-fdap-server/ --header 'Authorization: Bearer ROOT_TOKEN' --data @fdap.json`.

Note that this will replace all data at `/`. If you have different processes managing FDAP steate you'll need to do more piecewise updates to individual subpaths.

# OpenFDAP ontology

- `"fdap_user"` - record, each key is an FDAP token (optional)

  This is merged with the identical field in the openfdap config, allowing you to configure new applications while running.

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
