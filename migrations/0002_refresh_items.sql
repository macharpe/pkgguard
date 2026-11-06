-- The work list of one refresh run. A step result is capped at 1 MiB, so the plan lives here, not in the Workflow.
-- `status` records each item's outcome so the sync high-water mark can never advance past a record that failed.
CREATE TABLE refresh_items (
  run_id    TEXT NOT NULL,
  seq       INTEGER NOT NULL,             -- processing order, oldest modification first
  ecosystem TEXT NOT NULL,
  osv_id    TEXT NOT NULL,
  modified  TEXT NOT NULL,                -- as listed in modified_id.csv
  status    TEXT NOT NULL DEFAULT 'pending',  -- pending | done | missing | failed
  PRIMARY KEY (run_id, seq)
);
