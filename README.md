# bjorst-rate-limiter

Sliding-window rate limiter (in-memory), keyed by IP address or by anything
hashable.

## Usage

```toml
[dependencies]
bjorst-rate-limiter = { git = "https://github.com/bjorstgroup/bjorst-rate-limiter", tag = "v0.2.0" }
```

```rust
use std::time::Duration;
use bjorst_rate_limiter::RateLimiter;

// 30 requests per hour per IP.
let limiter = Arc::new(RateLimiter::new(30, Duration::from_secs(3600)));

// In a handler or middleware:
match limiter.check(client_ip) {
    Ok(info) => {
        // Set RateLimit-Remaining: info.remaining
        // Set RateLimit-Reset: info.reset_unix
    }
    Err(info) => {
        // 429 Too Many Requests
        // Set Retry-After: info.reset_unix - now
    }
}
```

### Any key

The key defaults to `IpAddr`. Anything `Hash + Eq` works, such as an account or an
email address. An address limit alone does not stop an attack spread across many
addresses, so a sign-in usually wants both:

```rust
let per_ip: RateLimiter = RateLimiter::new(20, Duration::from_secs(900));
let per_account: RateLimiter<String> = RateLimiter::new(10, Duration::from_secs(900));
```

## Notes

- A denied request is not counted, so hammering a closed door does not keep it closed.

- **Sliding window** (not fixed bucket) — prevents burst-at-boundary attacks.
- **In-memory** — suitable for single-instance deployments. For horizontal scaling, replace with Redis sorted sets.
- Call `limiter.gc()` from a background task to reclaim memory for expired IPs.

```rust
tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(300));
    loop {
        interval.tick().await;
        limiter.gc();
    }
});
```
