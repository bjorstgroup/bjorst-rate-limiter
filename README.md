# bjorst-rate-limiter

Per-IP sliding-window rate limiter (in-memory).

## Usage

```toml
[dependencies]
bjorst-rate-limiter = { git = "https://github.com/bjorstgroup/bjorst-rate-limiter" }
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

## Notes

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
