This is a simple async FDAP client library for Rust.

Install it with: `cargo add fdap`.

Use it with:

```rust
let fdap_client = fdap::Client::builder().build()?;
let limits = htwrap::htreq::Limits::default();
let email = fdap_client.user_get(limits, "stephanie", ["email"]).await?;
```

The base URL and token are read from the `FDAP_BASE_URL` and `FDAP_TOKEN` environment variables unless set explicitly on the builder.
