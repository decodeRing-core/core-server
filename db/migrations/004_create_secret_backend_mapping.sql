CREATE TABLE secret_backend_mapping (
  app_id UUID NOT NULL REFERENCES applications(app_id),
  secret_name TEXT NOT NULL,
  backend TEXT NOT NULL,
  mount_path TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (app_id, secret_name)
);