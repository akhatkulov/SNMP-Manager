-- ═══════════════════════════════════════════════════════════════════════════
--  SNMP Manager — TimescaleDB Schema Migration
--  Run once against a fresh snmp_metrics database.
--  psql -U snmp -d snmp_metrics -f migrations/001_timescaledb_init.sql
-- ═══════════════════════════════════════════════════════════════════════════

-- ── Extension ────────────────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- ── Raw metrics hypertable ────────────────────────────────────────────────────
-- Every SNMP poll result and heartbeat ends up here.
-- Partitioned by 1-day chunks; 30-day rolling window via retention policy.
CREATE TABLE IF NOT EXISTS snmp_metrics (
    time          TIMESTAMPTZ      NOT NULL,
    device_ip     TEXT             NOT NULL,  -- INET cast at query time if needed
    hostname      TEXT,
    device_type   TEXT,
    oid           TEXT             NOT NULL,
    oid_name      TEXT,
    value         TEXT,            -- always TEXT for universality
    value_numeric DOUBLE PRECISION, -- nullable; populate in Go normalizer for numeric OIDs
    value_type    TEXT,            -- "Integer" | "Counter64" | "OctetString" etc.
    reason        TEXT DEFAULT 'changed' -- "new" | "changed" | "heartbeat"
);

-- Convert to hypertable — partitioned by 1 day.
-- 1-day chunks are the sweet spot for 30-day retention + efficient BRIN index.
SELECT create_hypertable(
    'snmp_metrics',
    'time',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);

-- Primary access pattern: device + OID + time window
CREATE INDEX IF NOT EXISTS idx_metrics_device_oid_time
    ON snmp_metrics (device_ip, oid, time DESC);

-- Full-table time-range scan (dashboard "last N hours" queries)
CREATE INDEX IF NOT EXISTS idx_metrics_time_brin
    ON snmp_metrics USING BRIN (time);

-- ── Trends table (hourly rollups) ─────────────────────────────────────────────
-- Pre-aggregated Min/Max/Avg/Count per device·OID·hour.
-- Populated by the continuous aggregate + housekeeping worker safety net.
CREATE TABLE IF NOT EXISTS snmp_trends (
    time_bucket  TIMESTAMPTZ NOT NULL,  -- truncated to 1-hour boundary
    device_ip    TEXT        NOT NULL,
    oid          TEXT        NOT NULL,
    oid_name     TEXT,
    val_min      DOUBLE PRECISION,
    val_max      DOUBLE PRECISION,
    val_avg      DOUBLE PRECISION,
    val_count    BIGINT,
    PRIMARY KEY (time_bucket, device_ip, oid)
);

-- Also hypertable for retention management (keep trends 1 year)
SELECT create_hypertable(
    'snmp_trends',
    'time_bucket',
    chunk_time_interval => INTERVAL '7 days',
    if_not_exists => TRUE
);

-- ── Continuous Aggregate ──────────────────────────────────────────────────────
-- Auto-materialised by TimescaleDB background worker — no manual cron needed.
-- Refresh policy: update every 1 hour, 1h lag, 3h lookback window.
CREATE MATERIALIZED VIEW IF NOT EXISTS snmp_trends_hourly
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 hour', time)  AS time_bucket,
    device_ip,
    oid,
    MAX(oid_name)                 AS oid_name,
    MIN(value_numeric)            AS val_min,
    MAX(value_numeric)            AS val_max,
    AVG(value_numeric)            AS val_avg,
    COUNT(*)                      AS val_count
FROM snmp_metrics
WHERE value_numeric IS NOT NULL
GROUP BY time_bucket('1 hour', time), device_ip, oid
WITH NO DATA;

SELECT add_continuous_aggregate_policy(
    'snmp_trends_hourly',
    start_offset      => INTERVAL '3 hours',
    end_offset        => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour',
    if_not_exists     => TRUE
);

-- ── Retention Policies ────────────────────────────────────────────────────────
-- Raw metrics: keep 30 days.
-- Chunk drops are O(1) filesystem unlink — zero WAL, zero VACUUM pressure.
SELECT add_retention_policy(
    'snmp_metrics',
    INTERVAL '30 days',
    if_not_exists => TRUE
);

-- Hourly trends: keep 1 year (tiny footprint compared to raw data).
SELECT add_retention_policy(
    'snmp_trends_hourly',
    INTERVAL '365 days',
    if_not_exists => TRUE
);

-- ── Verification ─────────────────────────────────────────────────────────────
SELECT
    hypertable_name,
    num_chunks,
    compression_enabled
FROM timescaledb_information.hypertables
WHERE hypertable_name IN ('snmp_metrics', 'snmp_trends');
