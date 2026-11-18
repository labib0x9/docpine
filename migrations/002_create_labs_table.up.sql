CREATE TABLE IF NOT EXISTS labs (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT        NOT NULL,
    tests       TEXT[]      NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS user_repo (
    user_id     BIGINT      PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    github_repo TEXT        NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS lab_run (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    lab_id      BIGINT      NOT NULL REFERENCES labs(id) ON DELETE CASCADE,
    github_repo TEXT        NOT NULL,
    status      TEXT        NOT NULL DEFAULT 'queued',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at  TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS lab_run_user_id_idx ON lab_run (user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS lab_result (
    id          BIGSERIAL PRIMARY KEY,
    run_id      BIGINT      NOT NULL UNIQUE REFERENCES lab_run(id) ON DELETE CASCADE,
    user_id     BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    github_repo TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    lab_id      BIGINT      NOT NULL REFERENCES labs(id) ON DELETE CASCADE,
    results     TEXT        NOT NULL DEFAULT ''
);
