This is a reference implementation suitable for small (single-server) deploys.

At the moment it stores the config as a single file on disk updated with atomic writes.

This also means that requests do not need to be paused to maintain consistency when taking backups.

Install it with: `cargo build`

It requires a configuration file like:

```json
{
  "bind_addr": "127.0.0.1:17778",
  "data_dir": "/var/fdap/database.json",
  "users": {
    "root_token": [[[], { "read": true, "write": true }]],
    "app1_token": [
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
