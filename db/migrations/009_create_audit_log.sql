CREATE TABLE audit_log (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id INTEGER,
    app_id VARCHAR(255),
    action VARCHAR(255) NOT NULL,
    denied BOOLEAN NOT NULL,
    reason TEXT
);
