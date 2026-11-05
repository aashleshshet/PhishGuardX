CREATE TABLE IF NOT EXISTS scan_history (
  id UUID NOT NULL,
  owner CHAR(64) NOT NULL,
  kind VARCHAR(12) NOT NULL CHECK (kind IN ('url','email','qr','screenshot')),
  risk VARCHAR(8) NOT NULL CHECK (risk IN ('low','review','high')),
  signal_count SMALLINT NOT NULL CHECK (signal_count BETWEEN 0 AND 100),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (id, owner)
);
CREATE INDEX IF NOT EXISTS scan_history_owner_created ON scan_history(owner, created_at DESC);
