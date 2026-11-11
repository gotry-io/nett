-- Hub data (design/hub.md section 8). Only nodes and node_updates grow over time, at most one row
-- per machine, with the count bounded by the site's upper limit.

-- Link: the hash and expiry of the random secret in the one-time link code (cleared after use), the
-- trust anchor pinned at link time, the site's owner token
CREATE TABLE hub (
    id INTEGER PRIMARY KEY NOT NULL CHECK (id = 1),
    url TEXT NOT NULL,
    link_secret_hash BLOB,
    link_expires_at INTEGER,
    trust_anchors TEXT,
    owner_token_id TEXT,
    owner_token_hash BLOB
);

-- The most recently pushed site state and generation
CREATE TABLE site (
    id INTEGER PRIMARY KEY NOT NULL CHECK (id = 1),
    generation INTEGER NOT NULL,
    state TEXT NOT NULL,
    pushed_at INTEGER NOT NULL
);

-- The latest record per machine: last connection, version, apply result and the mesh process's
-- local status
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
    -- Public address learned by the Hub (design/hub.md section 5, JSON of
    -- nett_site::state::Learned)
    learned TEXT,
    -- The machine's answer to the release manifest (design/release.md section 7)
    upgrade_result TEXT,
    upgrade_reason TEXT
);

-- Events that happen on the Hub side and are not yet in the pushed site state (design/hub.md
-- section 4): the admission material submitted at enrollment (JSON) and the time of departure.
-- Deleted once the pushed site state contains them
CREATE TABLE node_updates (
    node_id TEXT PRIMARY KEY NOT NULL,
    enrolled TEXT,
    left_at INTEGER
);
