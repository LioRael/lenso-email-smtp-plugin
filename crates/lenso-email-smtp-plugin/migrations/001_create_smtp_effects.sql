CREATE TABLE smtp_dispatch_effects (
    idempotency_key_hash text PRIMARY KEY CHECK (idempotency_key_hash ~ '^sha256:[0-9a-f]{64}$'),
    delivery_id_hash text NOT NULL CHECK (delivery_id_hash ~ '^sha256:[0-9a-f]{64}$'),
    attempt_id_hash text NOT NULL CHECK (attempt_id_hash ~ '^sha256:[0-9a-f]{64}$'),
    request_fingerprint text NOT NULL CHECK (request_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
    content_digest text NOT NULL CHECK (content_digest ~ '^sha256:[0-9a-f]{64}$'),
    state text NOT NULL CHECK (state IN ('prepared','sending','accepted','temporary_failure','permanent_failure','delivery_unknown')),
    fence bigint NOT NULL DEFAULT 0 CHECK (fence >= 0),
    effect_started_at timestamptz,
    lease_expires_at timestamptz,
    response jsonb,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    UNIQUE (delivery_id_hash, attempt_id_hash),
    CHECK ((state IN ('prepared','sending')) = (response IS NULL)),
    CHECK (state <> 'prepared' OR (effect_started_at IS NULL AND lease_expires_at IS NULL)),
    CHECK (state <> 'sending' OR (effect_started_at IS NOT NULL AND lease_expires_at IS NOT NULL))
);

CREATE INDEX smtp_dispatch_effects_expired_sending_idx
    ON smtp_dispatch_effects (lease_expires_at, idempotency_key_hash)
    WHERE state = 'sending';
