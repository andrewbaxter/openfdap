This is an FDAP client library for Rust.

Install it with: `cargo add fdap`.

Use it with:

```rust
let fdap_client = fdap::Client::builder().build()?;
let email = fdap_client.user_get("stephanie", ["email"]).await?;
```
