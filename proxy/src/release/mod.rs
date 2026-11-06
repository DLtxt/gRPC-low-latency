//! Release keys: signing software releases the proxy has read, instead of whatever it is
//! sent (M11).
//!
//! The same pattern as transfer keys (M10), applied to a key that signs software rather
//! than moving value. A release signature is what an updater or a package manager checks
//! before it installs something, so a build system that can get anything signed can ship
//! anything to every user. Here the build system describes the release in fields -- the
//! artifact, the version, the channel, and the SHA-256 of the file -- and the proxy
//! checks them and builds the statement it signs.
//!
//! * `statement` -- the release format: the exact bytes a release key signs.
//! * `policy` -- per key: the artifacts it releases, the channels it signs on its own
//!   and the ones that wait for approvers, an hourly cap, and who approves.
//! * `guard` -- applies all of it: sign now, hold for approval, or refuse.
//!
//! Shared with transfer keys: the token marker that stops the generic `Sign`
//! (`pkcs11::Purpose::Release`), the rolling window behind the cap (`crate::velocity`),
//! and holding and approving (`crate::approval`).
//!
//! See docs/m11-release-keys.md for the design and what this does not cover.

pub mod guard;
pub mod policy;
pub mod statement;

pub use guard::{Outcome, Refusal, ReleaseGuard, ReleaseRequest, Reservation};
pub use policy::ReleasePolicy;
pub use statement::Release;
