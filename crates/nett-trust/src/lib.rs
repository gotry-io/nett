//! Verification of signed payloads, trust anchors, admission material and revocations, shared by
//! nett-node and the mesh process (design/auth.md).
//!
//! The encoding rules are in design/auth.md section 10.5. This crate only verifies; the code that
//! generates signatures is in the `signing` feature, which is only for lab tools and tests.

pub mod admission;
pub mod anchors;
pub mod canonical;
pub mod encoding;
pub mod keys;
pub mod payload;
pub mod revocation;
pub mod signed;
#[cfg(any(test, feature = "signing"))]
pub mod signing;
