-- A short code shown to the developer, in the Chat alert and on the detection row, so a block can be found
-- from what the developer quotes. Nullable: only malware decisions get one, and existing rows have none.
ALTER TABLE detections ADD COLUMN reference TEXT;
CREATE INDEX idx_det_reference ON detections (reference) WHERE reference IS NOT NULL;
