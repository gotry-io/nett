//! Site (design/site.md): machines, permissions and access rules maintained by commands, signing,
//! and composing each machine's desired state from the site. The signing tool `nett site` and the
//! Hub share this logic (design/hub.md section 4).

pub mod changes;
pub mod compose;
pub mod dir;
pub mod ops;
pub mod sign;
pub mod state;
pub mod updates;

use std::fmt::Display;

#[derive(Debug, thiserror::Error)]
pub enum SiteError {
    #[error("{0}")]
    Invalid(String),
    #[error("signing: {0}")]
    Sign(String),
    #[error("{context}: {source}")]
    Io {
        context: String,
        source: std::io::Error,
    },
}

impl SiteError {
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }

    pub fn sign(e: impl Display) -> Self {
        Self::Sign(e.to_string())
    }

    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }
}

#[cfg(test)]
mod tests;
