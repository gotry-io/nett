//! 站点（design/site.md）：用命令维护的机器、权限与访问规则，签名，以及按站点组成各台机器的期望状态。
//! 签名工具 `nett site` 与 Hub 共用这一份逻辑（design/hub.md 第 4 节）。

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
