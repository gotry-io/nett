//! 组网进程的主循环：从配置来源取期望状态，交给引擎应用，直到收到退出信号。
//!
//! 退出时不删除组网接口：内核中的 WireGuard 照常工作，组网进程重启期间进行中的连接不中断。

use std::future::Future;

use crate::config::{ConfigError, DesiredMesh};
use crate::dataplane::DataPlane;
use crate::engine::Engine;
use crate::event::{Event, EventSink};

/// 期望状态的来源。实验构建从本地文件读取；接入 Hub 之后由 nett-node 经本机接口提供
/// （design/prototype.md 第 3 节）。
pub trait ConfigSource {
    /// 下一份期望状态；`None` 表示来源已关闭。
    fn next(&mut self) -> impl Future<Output = Option<Result<DesiredMesh, ConfigError>>> + Send;
}

#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error("applying the desired state panicked; this is a bug: {0}")]
    Panicked(String),
}

pub async fn run<S, D, E>(
    mut source: S,
    mut engine: Engine<D>,
    mut events: E,
    shutdown: impl Future<Output = ()>,
) -> Result<(), RunError>
where
    S: ConfigSource,
    D: DataPlane + 'static,
    E: EventSink + Send + 'static,
{
    tokio::pin!(shutdown);
    loop {
        let next = tokio::select! {
            () = &mut shutdown => return Ok(()),
            next = source.next() => next,
        };
        let Some(next) = next else {
            return Ok(());
        };
        // 数据面操作是阻塞的系统调用（netlink），放到阻塞线程池中执行
        let applied = tokio::task::spawn_blocking(move || {
            match next {
                Ok(desired) => engine.apply(&desired, &mut events),
                Err(e) => events.emit(Event::ConfigRejected {
                    reason: e.to_string(),
                }),
            }
            (engine, events)
        })
        .await;
        (engine, events) = applied.map_err(|e| RunError::Panicked(e.to_string()))?;
    }
}
