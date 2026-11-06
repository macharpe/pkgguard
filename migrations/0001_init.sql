-- Distilled OSV records. One row per (ecosystem, osv_id, package_name).
CREATE TABLE advisories (
  ecosystem    TEXT NOT NULL,
  osv_id       TEXT NOT NULL,
  package_name TEXT NOT NULL,
  namespace    TEXT,
  kind         TEXT NOT NULL,            -- 'malware' | 'vulnerability' — derived per §3.5, NOT from the ID prefix alone
  cwe_ids      TEXT,                     -- comma-separated, retained so the classifier can be re-run without a refetch
  severity     TEXT,                     -- CRITICAL | HIGH | MODERATE | LOW | NULL
  summary      TEXT,
  ranges_json  TEXT NOT NULL,            -- serialized OSV affected[].ranges + versions
  withdrawn    INTEGER NOT NULL DEFAULT 0,
  modified     TEXT NOT NULL,            -- ISO8601, from OSV
  PRIMARY KEY (ecosystem, osv_id, package_name)  -- one OSV record can affect several packages (event-stream + flatmap-stream)
);
CREATE INDEX idx_adv_pkg  ON advisories (ecosystem, package_name);
CREATE INDEX idx_adv_mod  ON advisories (modified DESC);
CREATE INDEX idx_adv_kind ON advisories (kind, severity);

-- One row per refresh, drives the progress bar and the history view.
CREATE TABLE refresh_runs (
  id            TEXT PRIMARY KEY,         -- Workflow instance id
  kind          TEXT NOT NULL,            -- 'monthly' | 'daily-malware' | 'manual' | 'bootstrap'
  trigger       TEXT NOT NULL,            -- 'cron' | email | 'service-token'
  status        TEXT NOT NULL,            -- queued | running | complete | failed
  phase         TEXT,                     -- human-readable current phase
  items_done    INTEGER NOT NULL DEFAULT 0,
  items_total   INTEGER NOT NULL DEFAULT 0,
  added         INTEGER NOT NULL DEFAULT 0,
  updated       INTEGER NOT NULL DEFAULT 0,
  removed       INTEGER NOT NULL DEFAULT 0,
  errors        INTEGER NOT NULL DEFAULT 0,
  error_detail  TEXT,
  started_at    TEXT NOT NULL,
  finished_at   TEXT
);

-- Per-ecosystem high-water mark for delta sync.
CREATE TABLE sync_state (
  ecosystem      TEXT PRIMARY KEY,
  last_modified  TEXT NOT NULL,           -- newest ISO8601 seen in modified_id.csv
  record_count   INTEGER NOT NULL DEFAULT 0,
  last_synced_at TEXT NOT NULL
);

-- What the filter Worker saw.
CREATE TABLE detections (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ts          TEXT NOT NULL,
  ecosystem   TEXT NOT NULL,
  package_name TEXT NOT NULL,
  version     TEXT,
  purl        TEXT,
  verdict     TEXT NOT NULL,              -- blocked | flagged | allowed | error
  reason      TEXT,                       -- osv-malware | osv-cve | override | lookup-error
  osv_ids     TEXT,                       -- comma-separated
  user_email  TEXT,                       -- from context.identity()
  src_ip      TEXT,
  source      TEXT                        -- index | live-osv | override
);
CREATE INDEX idx_det_ts      ON detections (ts DESC);
CREATE INDEX idx_det_verdict ON detections (verdict, ts DESC);

-- Manual overrides, mirrored into KV on write.
CREATE TABLE overrides (
  ecosystem    TEXT NOT NULL,
  package_name TEXT NOT NULL,
  mode         TEXT NOT NULL,             -- 'block' | 'allow'
  version_spec TEXT,                      -- NULL = all versions
  note         TEXT,
  created_by   TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  PRIMARY KEY (ecosystem, package_name, mode)
);

-- Append-only audit of admin mutations.
CREATE TABLE audit_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  ts         TEXT NOT NULL,
  actor      TEXT NOT NULL,               -- email or service-token client id
  action     TEXT NOT NULL,
  detail     TEXT
);
