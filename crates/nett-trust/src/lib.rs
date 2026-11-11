//! Verification of signed payloads, trust anchors, admission material and revocations, shared by
//! nett-node and the mesh process (design/auth.md).
//!
//! The encoding rules are in design/auth.md section 10.5. Release signatures are in [`release`].
//! Generating signatures is in the `signing` feature, used by the signing tool, by new machines
//! when they enroll, and by lab tools and tests; the mesh process only verifies.

pub mod admission;
pub mod anchors;
pub mod canonical;
pub mod encoding;
pub mod keys;
pub mod payload;
pub mod release;
pub mod revocation;
pub mod signed;
#[cfg(any(test, feature = "signing"))]
pub mod signing;
