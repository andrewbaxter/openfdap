This is a reference implementation suitable for small (single-server) deploys.

At the moment it stores the config as a single file on disk updated with atomic writes.

This also means that requests do not need to be paused to maintain consistency when taking backups.

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

Make sure you create a root/admin user in the config above.

This is optional, but you can create a JSON-Schema file `fdap.schema.json` your FDAP data like:

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

Then edit your FDAP data file `fdap.json` with:

```json
{
  "$schema": "file://./fdap.schema.json",
  ...
}
```

And commit it with `curl -X POST https://my-fdap-server/ --header 'Authorization: Bearer ROOT_TOKEN' --data @fdap.json`.

Note that this will replace all data at `/`. If applications are writing directly to `FDAP` you'll need to do more piecewise updates to individual subpaths.
