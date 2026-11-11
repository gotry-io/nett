//! Hub 的存储（design/hub.md 第 8 节）：SQLite，显式设置缓存与 mmap 上限；查询用 `sqlx::query!` 在编译期检查，
//! 离线数据在仓库根目录的 `.sqlx/`。

use std::path::Path;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions};

/// SQLite 的页缓存上限（KiB，负数表示按大小）与 mmap 上限：Hub 稳定运行 ≤ 30–50 MB（硬性规则 14）。
const CACHE_KIB: i64 = 2048;
const MMAP_BYTES: i64 = 0;
const MAX_CONNECTIONS: u32 = 4;

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("database: {0}")]
    Sql(#[from] sqlx::Error),
    #[error("database migration: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
}

#[derive(Debug, Clone)]
pub struct Db {
    pool: SqlitePool,
}

#[derive(Debug, Clone)]
pub struct HubRow {
    pub url: String,
    pub trust_anchors: Option<String>,
    pub owner_token_hash: Option<Vec<u8>>,
}

/// 在 Hub 一侧发生、站点还没有取回的事。
#[derive(Debug, Clone)]
pub struct UpdateRow {
    pub node_id: String,
    pub enrolled: Option<String>,
    pub left_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct NodeRow {
    pub node_id: String,
    pub last_seen: i64,
    pub nett_version: Option<String>,
    pub platform: Option<String>,
    pub applied_generation: Option<i64>,
    pub ack_result: Option<String>,
    pub ack_reason: Option<String>,
    pub status: Option<String>,
    pub status_at: Option<i64>,
    pub learned: Option<String>,
}

impl Db {
    pub async fn open(path: &Path) -> Result<Self, DbError> {
        // 按文件名打开：路径中的空格和 `?` 不会被当成 URL 的一部分
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .pragma("cache_size", (-CACHE_KIB).to_string())
            .pragma("mmap_size", MMAP_BYTES.to_string())
            // 临时数据放在内存中：容器的根文件系统只读，没有可写的临时目录
            .pragma("temp_store", "memory")
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(MAX_CONNECTIONS)
            .connect_with(options)
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool })
    }

    /// 初始化或重新生成关联码：只在还没有关联站点时（`nett-hub reset` 之后）。
    pub async fn set_link(
        &self,
        url: &str,
        secret_hash: &[u8],
        expires_at: i64,
    ) -> Result<bool, DbError> {
        let linked = sqlx::query!("SELECT owner_token_id FROM hub WHERE id = 1")
            .fetch_optional(&self.pool)
            .await?
            .and_then(|r| r.owner_token_id)
            .is_some();
        if linked {
            return Ok(false);
        }
        sqlx::query!(
            "INSERT INTO hub (id, url, link_secret_hash, link_expires_at) VALUES (1, ?1, ?2, ?3)
             ON CONFLICT (id) DO UPDATE SET url = ?1, link_secret_hash = ?2, link_expires_at = ?3",
            url,
            secret_hash,
            expires_at
        )
        .execute(&self.pool)
        .await?;
        Ok(true)
    }

    pub async fn hub(&self) -> Result<Option<HubRow>, DbError> {
        Ok(sqlx::query_as!(
            HubRow,
            "SELECT url, trust_anchors, owner_token_hash FROM hub WHERE id = 1"
        )
        .fetch_optional(&self.pool)
        .await?)
    }

    /// 关联：关联码中的随机密钥对得上、没有过期、没用过时，固定信任锚并保存 owner token 的哈希。关联码
    /// 只能用一次：同一条语句中清空它。
    pub async fn link(
        &self,
        secret_hash: &[u8],
        now: i64,
        trust_anchors: &str,
        token_id: &str,
        token_hash: &[u8],
    ) -> Result<bool, DbError> {
        let done = sqlx::query!(
            "UPDATE hub SET link_secret_hash = NULL, link_expires_at = NULL, trust_anchors = ?3,
                 owner_token_id = ?4, owner_token_hash = ?5
             WHERE id = 1 AND link_secret_hash = ?1 AND link_expires_at > ?2 AND owner_token_id IS NULL",
            secret_hash,
            now,
            trust_anchors,
            token_id,
            token_hash
        )
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    pub async fn site(&self) -> Result<Option<(i64, String)>, DbError> {
        Ok(
            sqlx::query!("SELECT generation, state FROM site WHERE id = 1")
                .fetch_optional(&self.pool)
                .await?
                .map(|r| (r.generation, r.state)),
        )
    }

    pub async fn put_site(&self, generation: i64, state: &str, now: i64) -> Result<(), DbError> {
        sqlx::query!(
            "INSERT INTO site (id, generation, state, pushed_at) VALUES (1, ?1, ?2, ?3)
             ON CONFLICT (id) DO UPDATE SET generation = ?1, state = ?2, pushed_at = ?3",
            generation,
            state,
            now
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn seen(&self, node_id: &str, now: i64, version: &str) -> Result<(), DbError> {
        sqlx::query!(
            "INSERT INTO nodes (node_id, last_seen, nett_version) VALUES (?1, ?2, ?3)
             ON CONFLICT (node_id) DO UPDATE SET last_seen = ?2, nett_version = ?3",
            node_id,
            now,
            version
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn set_platform(&self, node_id: &str, platform: &str) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE nodes SET platform = ?2 WHERE node_id = ?1",
            node_id,
            platform
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn set_ack(
        &self,
        node_id: &str,
        generation: i64,
        result: &str,
        reason: &str,
    ) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE nodes SET applied_generation = ?2, ack_result = ?3, ack_reason = ?4 WHERE node_id = ?1",
            node_id,
            generation,
            result,
            reason
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn set_status(&self, node_id: &str, status: &str, now: i64) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE nodes SET status = ?2, status_at = ?3 WHERE node_id = ?1",
            node_id,
            status,
            now
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn nodes(&self) -> Result<Vec<NodeRow>, DbError> {
        Ok(sqlx::query_as!(
            NodeRow,
            "SELECT node_id, last_seen, nett_version, platform, applied_generation, ack_result,
                    ack_reason, status, status_at, learned
             FROM nodes ORDER BY node_id"
        )
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn set_learned(&self, node_id: &str, learned: &str) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE nodes SET learned = ?2 WHERE node_id = ?1",
            node_id,
            learned
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// 一台机器入网时交来的准入材料。
    pub async fn put_enrolled(&self, node_id: &str, material: &str) -> Result<(), DbError> {
        sqlx::query!(
            "INSERT INTO node_updates (node_id, enrolled) VALUES (?1, ?2)
             ON CONFLICT (node_id) DO UPDATE SET enrolled = ?2",
            node_id,
            material
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// 一台机器自行退出。
    pub async fn put_left(&self, node_id: &str, now: i64) -> Result<(), DbError> {
        sqlx::query!(
            "INSERT INTO node_updates (node_id, left_at) VALUES (?1, ?2)
             ON CONFLICT (node_id) DO UPDATE SET left_at = ?2",
            node_id,
            now
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn updates(&self) -> Result<Vec<UpdateRow>, DbError> {
        Ok(sqlx::query_as!(
            UpdateRow,
            "SELECT node_id, enrolled, left_at FROM node_updates ORDER BY node_id"
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// 站点已经有了的事：入网的准入材料（`enrolled`）、退出（`left`）。两者都没有了时删除这一行。
    pub async fn acknowledge(
        &self,
        node_id: &str,
        enrolled: bool,
        left: bool,
    ) -> Result<(), DbError> {
        if enrolled {
            sqlx::query!(
                "UPDATE node_updates SET enrolled = NULL WHERE node_id = ?1",
                node_id
            )
            .execute(&self.pool)
            .await?;
        }
        if left {
            sqlx::query!(
                "UPDATE node_updates SET left_at = NULL WHERE node_id = ?1",
                node_id
            )
            .execute(&self.pool)
            .await?;
        }
        sqlx::query!(
            "DELETE FROM node_updates WHERE node_id = ?1 AND enrolled IS NULL AND left_at IS NULL",
            node_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// 不在站点中的机器不再保留（保留策略：一台机器一行）。
    pub async fn prune(&self, keep: &[String]) -> Result<(), DbError> {
        for row in self.nodes().await? {
            if !keep.contains(&row.node_id) {
                sqlx::query!("DELETE FROM nodes WHERE node_id = ?1", row.node_id)
                    .execute(&self.pool)
                    .await?;
            }
        }
        Ok(())
    }

    /// `nett-hub reset`：作废与站点的关联，删除站点与各台机器的数据。
    pub async fn reset(&self) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query!("DELETE FROM site").execute(&mut *tx).await?;
        sqlx::query!("DELETE FROM nodes").execute(&mut *tx).await?;
        sqlx::query!("DELETE FROM node_updates")
            .execute(&mut *tx)
            .await?;
        sqlx::query!(
            "UPDATE hub SET link_secret_hash = NULL, link_expires_at = NULL, trust_anchors = NULL,
                 owner_token_id = NULL, owner_token_hash = NULL"
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }
}
