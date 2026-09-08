//! Keeping the tail latency of healthy traffic intact when the service is under stress.
//!
//! Three mechanisms, each answering a different failure:
//!
//! * `breaker` -- the token is broken, so stop paying full price to discover that.
//! * `ratelimit` -- one caller is greedy, so stop them from spending everyone's capacity.
//! * bounded queue + load shed (in `pkcs11::pool`) -- more work has arrived than can be
//!   served, so refuse the excess instead of queueing it.
//!
//! All three share one principle: under overload, reject quickly rather than accept
//! slowly. A queued request that will miss its deadline anyway has consumed capacity for
//! nothing, and worse, has pushed out the latency of requests that would have made it.

pub mod breaker;
pub mod ratelimit;

pub use breaker::{BreakerConfig, CircuitBreaker, State as BreakerState};
pub use ratelimit::{RateLimitConfig, RateLimiter};
