CREATE TABLE applications (
  app_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  app_name TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
