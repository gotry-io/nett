//! 组网进程的主循环：从配置来源取期望状态，交给后台线程应用，直到收到退出信号。
//!
//! 退出时不删除组网接口：内核中的 WireGuard 照常工作，组网进程重启期间进行中的连接不中断。

use std::future::Future;

use crate::config::{ConfigError, DesiredMesh};
use crate::status::ReloadReply;

/// 交付的一份期望状态。`reply` 是经本机接口请求重新读取（`nett reload`）、在等应用结果的一方
/// （design/status.md 第 4.1 节）；启动时的读取与 `SIGHUP` 没有。
pub struct Delivery {
    pub desired: Result<DesiredMesh, ConfigError>,
    pub reply: Option<ReloadReply>,
}

/// 期望状态的来源。实验构建从本地文件读取；接入 Hub 之后由 nett-node 经本机接口提供
/// （design/prototype.md 第 3 节）。
pub trait ConfigSource {
    /// 下一份期望状态；`None` 表示来源已关闭。
    fn next(&mut self) -> impl Future<Output = Option<Delivery>> + Send;
}

/// 接收期望状态的一方（组网进程的后台线程）。调用可能阻塞，由 [`run`] 放到阻塞线程池中执行。
pub trait Applier: Send + 'static {
    fn apply(&mut self, delivery: Delivery);
}

#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error("handing over the desired state panicked; this is a bug: {0}")]
    Panicked(String),
}

/// 把配置来源交付的期望状态逐份交给 `applier`，直到来源关闭或收到退出信号。
pub async fn run<S, A>(
    mut source: S,
    mut applier: A,
    shutdown: impl Future<Output = ()>,
) -> Result<A, RunError>
where
    S: ConfigSource,
    A: Applier,
{
    tokio::pin!(shutdown);
    loop {
        let next = tokio::select! {
            () = &mut shutdown => return Ok(applier),
            next = source.next() => next,
        };
        let Some(next) = next else {
            return Ok(applier);
        };
        applier = tokio::task::spawn_blocking(move || {
            applier.apply(next);
            applier
        })
        .await
        .map_err(|e| RunError::Panicked(e.to_string()))?;
    }
}
