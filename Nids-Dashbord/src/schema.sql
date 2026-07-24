-- ============================================================
-- NIDS Dashboard - SQLite Database Schema
-- ============================================================

-- Main alerts table
CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT NOT NULL,
    signature       TEXT NOT NULL,
    signature_id    INTEGER NOT NULL,
    category        TEXT,
    severity        INTEGER,
    protocol        TEXT,
    src_ip          TEXT NOT NULL,
    src_port        INTEGER,
    dest_ip         TEXT NOT NULL,
    dest_port       INTEGER,
    attack_type     TEXT,
    raw_json        TEXT,
    created_at      TEXT DEFAULT CURRENT_TIMESTAMP
);

-- SID -> attack type mapping table
CREATE TABLE IF NOT EXISTS sid_mapping (
    signature_id    INTEGER PRIMARY KEY,
    attack_type     TEXT NOT NULL
);

-- Blocked IPs table (Response Engine)
CREATE TABLE IF NOT EXISTS blocked_ips (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address      TEXT NOT NULL UNIQUE,
    reason          TEXT,
    triggered_by_sid INTEGER,
    alert_count     INTEGER,
    blocked_at      TEXT DEFAULT CURRENT_TIMESTAMP,
    status          TEXT DEFAULT 'active',
    unblocked_at    TEXT
);

-- Response Engine action log
CREATE TABLE IF NOT EXISTS response_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    action_type     TEXT NOT NULL,
    target_ip       TEXT,
    details         TEXT,
    success         BOOLEAN,
    timestamp       TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for dashboard query performance
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_attack_type ON alerts(attack_type);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_signature_id ON alerts(signature_id);

-- Initial population of sid_mapping based on custom Suricata rules
INSERT OR IGNORE INTO sid_mapping (signature_id, attack_type) VALUES
    (1000001, 'Nikto'),
    (1000002, 'Nmap'),
    (1000003, 'Nmap'),
    (1000004, 'Nmap'),
    (1000005, 'Nmap'),
    (1000006, 'Nmap'),
    (1000007, 'Hydra'),
    (1000008, 'Hydra'),
    (1000009, 'hping3'),
    (1000010, 'hping3');
