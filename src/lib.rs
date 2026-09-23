//! Sliding-window rate limiter (in-memory), keyed by IP address or by
//! anything else.
//!
//! The key defaults to [`IpAddr`], which is what the limiter was first written
//! for. Any `Hash + Eq + Clone` key works: an account, an email address, a
//! `(route, ip)` pair. An address limit alone does not stop an attack spread
//! across many addresses, so a sign-in usually wants one of each.
//!
//! ## Design
//!
//! - In-memory: sufficient for single-instance deployments.
//!   Swap to Redis sorted-sets when horizontal scaling is needed.
//! - Sliding window (not fixed bucket) prevents burst-at-boundary.
//! - Periodic [`RateLimiter::gc`] keeps memory bounded.
//!
//! ## Usage
//!
//! ```no_run
//! use std::time::Duration;
//! use std::net::{IpAddr, Ipv4Addr};
//! use bjorst_rate_limiter::RateLimiter;
//!
//! let limiter = RateLimiter::new(30, Duration::from_secs(3600));
//! let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
//!
//! match limiter.check(ip) {
//!     Ok(info) => println!("allowed, {} remaining", info.remaining),
//!     Err(info) => println!("rate limited, resets at {}", info.reset_unix),
//! }
//! ```

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// A sliding-window limit per key: at most `max_requests` within any
/// `window`. The key defaults to [`IpAddr`].
pub struct RateLimiter<K = IpAddr> {
    max_requests: u32,
    window: Duration,
    buckets: Mutex<HashMap<K, VecDeque<Instant>>>,
}

/// Outcome of a rate-limit check. Carry values to `RateLimit-*` response headers.
#[derive(Debug)]
pub struct RateCheck {
    pub limit: u32,
    pub remaining: u32,
    /// Approximate Unix timestamp when the oldest request in the window expires.
    pub reset_unix: u64,
}

impl<K: Hash + Eq> RateLimiter<K> {
    /// At most `max_requests` per key within any `window`.
    pub fn new(max_requests: u32, window: Duration) -> Self {
        Self {
            max_requests,
            window,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Returns `Ok(info)` if the request is allowed, `Err(info)` if denied.
    /// A denied request is not counted.
    pub fn check(&self, key: K) -> Result<RateCheck, RateCheck> {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().expect("rate limiter poisoned");

        let entries = buckets.entry(key).or_default();

        // `checked_sub`: a window longer than the monotonic clock has been
        // running (a freshly booted host) would otherwise panic. Nothing can
        // have expired yet in that case.
        if let Some(cutoff) = now.checked_sub(self.window) {
            while entries.front().is_some_and(|t| *t < cutoff) {
                entries.pop_front();
            }
        }

        let reset_unix =
            Self::instant_to_unix(entries.front().copied().unwrap_or(now) + self.window);

        if entries.len() as u32 >= self.max_requests {
            return Err(RateCheck {
                limit: self.max_requests,
                remaining: 0,
                reset_unix,
            });
        }

        entries.push_back(now);
        Ok(RateCheck {
            limit: self.max_requests,
            remaining: self.max_requests - entries.len() as u32,
            reset_unix,
        })
    }

    /// Remove keys whose entire window has expired. Call periodically from a
    /// background task.
    pub fn gc(&self) {
        let Some(cutoff) = Instant::now().checked_sub(self.window) else {
            return;
        };
        let mut buckets = self.buckets.lock().expect("rate limiter poisoned");
        buckets.retain(|_, entries| {
            while entries.front().is_some_and(|t| *t < cutoff) {
                entries.pop_front();
            }
            !entries.is_empty()
        });
    }

    fn instant_to_unix(target: Instant) -> u64 {
        let now_mono = Instant::now();
        let now_wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if target > now_mono {
            now_wall + (target - now_mono).as_secs()
        } else {
            now_wall.saturating_sub((now_mono - target).as_secs())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn allows_up_to_limit() {
        let rl = RateLimiter::new(3, Duration::from_secs(3600));
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        assert!(rl.check(ip).is_ok());
        assert!(rl.check(ip).is_ok());
        assert!(rl.check(ip).is_ok());
        assert!(rl.check(ip).is_err());
    }

    #[test]
    fn separate_ips_have_separate_buckets() {
        let rl = RateLimiter::new(1, Duration::from_secs(3600));
        let ip_a = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));

        assert!(rl.check(ip_a).is_ok());
        assert!(rl.check(ip_a).is_err());
        assert!(rl.check(ip_b).is_ok());
    }

    #[test]
    fn remaining_decrements() {
        let rl = RateLimiter::new(5, Duration::from_secs(3600));
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        let info = rl.check(ip).unwrap();
        assert_eq!(info.remaining, 4);
        let info = rl.check(ip).unwrap();
        assert_eq!(info.remaining, 3);
    }

    #[test]
    fn any_hashable_key_works() {
        let rl: RateLimiter<String> = RateLimiter::new(1, Duration::from_secs(3600));

        assert!(rl.check("ada@example.com".to_owned()).is_ok());
        assert!(rl.check("ada@example.com".to_owned()).is_err());
        assert!(rl.check("bo@example.com".to_owned()).is_ok());
    }

    #[test]
    fn a_denied_request_is_not_counted() {
        let rl = RateLimiter::new(1, Duration::from_millis(20));
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        assert!(rl.check(ip).is_ok());
        for _ in 0..5 {
            assert!(rl.check(ip).is_err());
        }
        std::thread::sleep(Duration::from_millis(30));
        assert!(rl.check(ip).is_ok(), "denials extended the window");
    }

    #[test]
    fn a_window_longer_than_uptime_does_not_panic() {
        let rl = RateLimiter::new(1, Duration::from_secs(u64::MAX / 4));
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

        assert!(rl.check(ip).is_ok());
        assert!(rl.check(ip).is_err());
        rl.gc();
    }

    #[test]
    fn gc_removes_stale_entries() {
        let rl = RateLimiter::new(100, Duration::from_millis(1));
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        rl.check(ip).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        rl.gc();

        let info = rl.check(ip).unwrap();
        assert_eq!(info.remaining, 99);
    }
}
