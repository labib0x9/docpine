-- Docpine Runtime Security & Isolation Monitoring Schema

CREATE TABLE IF NOT EXISTS containers (
    id              TEXT PRIMARY KEY,          -- Docpine sandbox ID
    cgroup_id       BIGINT UNIQUE NOT NULL,    -- Kernel cgroup ID
    backend         TEXT NOT NULL DEFAULT 'docker', -- 'docker' | 'gvisor'
    created_at      TIMESTAMPTZ NOT NULL,
    baseline_ns     JSONB,                     -- NamespaceIdentity baseline
    baseline_caps   BIGINT,                    -- Initial effective caps bitmask
    host_exposure   JSONB,                     -- Host mounts, privileged, docker socket
    terminated_at   TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS processes (
    cgroup_id       BIGINT NOT NULL,
    pid             INT NOT NULL,
    ppid            INT,
    comm            TEXT,
    started_at      TIMESTAMPTZ NOT NULL,
    exited_at       TIMESTAMPTZ,
    PRIMARY KEY (cgroup_id, pid, started_at)
);

CREATE TABLE IF NOT EXISTS events (
    id              BIGSERIAL PRIMARY KEY,
    cgroup_id       BIGINT NOT NULL,
    pid             INT NOT NULL,
    event_type      TEXT NOT NULL,             -- exec, openat, connect, setns, unshare...
    data            JSONB,
    occurred_at     TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_cgroup_time ON events (cgroup_id, occurred_at DESC);

CREATE TABLE IF NOT EXISTS findings (
    id              BIGSERIAL PRIMARY KEY,
    container_id    TEXT REFERENCES containers(id),
    pid             INT,
    severity        TEXT NOT NULL,             -- low, medium, high, critical
    finding_type    TEXT NOT NULL,             -- SHELL_TO_EXFIL, PRIVILEGE_CHANGE...
    summary         TEXT,
    event_ids       BIGINT[],                  -- Supporting event IDs
    created_at      TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_container ON findings (container_id, created_at DESC);

CREATE TABLE IF NOT EXISTS policies (
    container_id         TEXT PRIMARY KEY REFERENCES containers(id),
    allowed_capabilities TEXT[],
    network_rules        JSONB,
    fs_rules             JSONB,
    updated_at           TIMESTAMPTZ NOT NULL
);
