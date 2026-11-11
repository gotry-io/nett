-- Hub 的数据（design/hub.md 第 8 节）。持续增长的只有 nodes 与 node_updates，一台机器至多一行，数量受站点的
-- 上限约束。

-- 关联：一次性关联码中随机密钥的哈希与过期时间（用过之后清空），关联时固定的信任锚，站点的 owner token
CREATE TABLE hub (
    id INTEGER PRIMARY KEY NOT NULL CHECK (id = 1),
    url TEXT NOT NULL,
    link_secret_hash BLOB,
    link_expires_at INTEGER,
    trust_anchors TEXT,
    owner_token_id TEXT,
    owner_token_hash BLOB
);

-- 最近一次推送的站点状态与代数
CREATE TABLE site (
    id INTEGER PRIMARY KEY NOT NULL CHECK (id = 1),
    generation INTEGER NOT NULL,
    state TEXT NOT NULL,
    pushed_at INTEGER NOT NULL
);

-- 每台机器最新的一份：最近一次连接、版本、应用结果与组网进程的本机状态
CREATE TABLE nodes (
    node_id TEXT PRIMARY KEY NOT NULL,
    last_seen INTEGER NOT NULL,
    nett_version TEXT,
    platform TEXT,
    applied_generation INTEGER,
    ack_result TEXT,
    ack_reason TEXT,
    status TEXT,
    status_at INTEGER,
    -- Hub 得知的公网地址（design/hub.md 第 5 节，nett_site::state::Learned 的 JSON）
    learned TEXT
);

-- 在 Hub 一侧发生、站点推送的状态中还没有的事（design/hub.md 第 4 节）：入网时交来的准入材料（JSON）与
-- 退出的时间。推送的站点状态中已经有了时删除
CREATE TABLE node_updates (
    node_id TEXT PRIMARY KEY NOT NULL,
    enrolled TEXT,
    left_at INTEGER
);
