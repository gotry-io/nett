//! Hub storage (design/hub.md section 8): SQLite with explicitly set cache and mmap limits; queries
//! are checked at compile time with `sqlx::query!`, and the offline data is in `.sqlx/` at the
//! repository root.

use std::path::Path;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions};

/// SQLite's page cache limit (KiB, a negative number means by size) and mmap limit: the Hub's
/// steady-state use is ≤ 30-50 MB (hard rule 14).
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

/// Events that happen on the Hub side and that the site has not yet fetched.
#[derive(Debug, Clone)]
pub struct UpdateRow {
    pub node_id: String,
    pub enrolled: Option<String>,
    pub left_at: Option<i64>,
}

/// One event of a machine (design/hub.md section 8).
#[derive(Debug, Clone)]
pub struct EventRow {
    pub at: i64,
    pub kind: String,
    pub detail: String,
}

/// Events kept per machine, and for how long.
pub const EVENTS_PER_NODE: i64 = 100;
pub const EVENTS_KEPT_SECS: i64 = 30 * 24 * 3600;

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
    pub upgrade_result: Option<String>,
    pub upgrade_reason: Option<String>,
}

impl Db {
    pub async fn open(path: &Path) -> Result<Self, DbError> {
        // Open by file name: spaces and `?` in the path are not treated as part of a URL
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .pragma("cache_size", (-CACHE_KIB).to_string())
            .pragma("mmap_size", MMAP_BYTES.to_string())
            // Temporary data is kept in memory: the container's root file system is read-only and
            // has no writable temporary directory
            .pragma("temp_store", "memory")
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(MAX_CONNECTIONS)
            .connect_with(options)
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool })
    }

    /// Initializes or regenerates the link code: only when no site is linked yet (after `nett-hub
    /// reset`).
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

    /// Link: when the random secret in the link code matches, has not expired and has not been
    /// used, pins the trust anchor and saves the hash of the owner token. The link code
    /// can be used only once: it is cleared in the same statement.
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
                    ack_reason, status, status_at, learned, upgrade_result, upgrade_reason
             FROM nodes ORDER BY node_id"
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// Records an event of a machine and drops what the retention policy no longer keeps.
    pub async fn add_event(
        &self,
        node_id: &str,
        at: i64,
        kind: &str,
        detail: &str,
    ) -> Result<(), DbError> {
        let oldest = at - EVENTS_KEPT_SECS;
        let mut tx = self.pool.begin().await?;
        sqlx::query!(
            "INSERT INTO events (node_id, at, kind, detail) VALUES (?1, ?2, ?3, ?4)",
            node_id,
            at,
            kind,
            detail
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query!(
            "DELETE FROM events WHERE node_id = ?1 AND id NOT IN
                 (SELECT id FROM events WHERE node_id = ?1 ORDER BY id DESC LIMIT ?2)",
            node_id,
            EVENTS_PER_NODE
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query!("DELETE FROM events WHERE at < ?1", oldest)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// A machine's most recent events, newest first.
    pub async fn events(&self, node_id: &str, limit: i64) -> Result<Vec<EventRow>, DbError> {
        Ok(sqlx::query_as!(
            EventRow,
            "SELECT at, kind, detail FROM events WHERE node_id = ?1 ORDER BY id DESC LIMIT ?2",
            node_id,
            limit
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// The machine's answer to the release manifest (design/release.md section 7).
    pub async fn set_upgrade(
        &self,
        node_id: &str,
        result: &str,
        reason: &str,
    ) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE nodes SET upgrade_result = ?2, upgrade_reason = ?3 WHERE node_id = ?1",
            node_id,
            result,
            reason
        )
        .execute(&self.pool)
        .await?;
        Ok(())
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

    /// The admission material submitted when a machine enrolls.
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

    /// A machine leaves on its own.
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

    /// Events the site already contains: the admission material of enrollment (`enrolled`), and
    /// leave (`left`). The row is deleted when both are gone.
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

    /// Machines not in the site are no longer kept (retention policy: one row per machine).
    pub async fn prune(&self, keep: &[String]) -> Result<(), DbError> {
        for row in self.nodes().await? {
            if !keep.contains(&row.node_id) {
                sqlx::query!("DELETE FROM nodes WHERE node_id = ?1", row.node_id)
                    .execute(&self.pool)
                    .await?;
                sqlx::query!("DELETE FROM events WHERE node_id = ?1", row.node_id)
                    .execute(&self.pool)
                    .await?;
            }
        }
        Ok(())
    }

    /// `nett-hub reset`: invalidates the link with the site and deletes the site and the data of
    /// each machine.
    pub async fn reset(&self) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query!("DELETE FROM site").execute(&mut *tx).await?;
        sqlx::query!("DELETE FROM nodes").execute(&mut *tx).await?;
        sqlx::query!("DELETE FROM node_updates")
            .execute(&mut *tx)
            .await?;
        sqlx::query!("DELETE FROM events").execute(&mut *tx).await?;
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
