//! Verification of signed payloads, trust anchors, admission material and revocations, shared by
//! nett-node and the mesh process (design/auth.md).
//!
//! The encoding rules are in design/auth.md section 10.5. Release signatures are in [`release`].
//! Generating signatures is in the `signing` feature, used by the signing tool, by new machines
//! when they enroll, and by lab tools and tests; the mesh process only verifies.

/// Largest sealed Hub backup anywhere (design/hub.md section 8.2).
pub const MAX_BACKUP_BYTES: usize = 4 << 20;

pub mod admission;
pub mod anchors;
#[cfg(feature = "backup")]
pub mod backup;
pub mod canonical;
pub mod encoding;
pub mod keys;
pub mod payload;
pub mod release;
pub mod revocation;
pub mod signed;
#[cfg(any(test, feature = "signing"))]
pub mod signing;
