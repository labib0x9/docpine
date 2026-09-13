package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/labib0x9/docpine/internal/domain/security"
	"github.com/lib/pq"
)

var (
	ErrNotFound = errors.New("record not found")
)

// ContainerRecord captures stored container metadata and security baselines.
type ContainerRecord struct {
	ID           string                     `json:"id"`
	CgroupID     uint64                     `json:"cgroup_id"`
	CreatedAt    time.Time                  `json:"created_at"`
	BaselineNS   security.NamespaceIdentity `json:"baseline_ns"`
	BaselineCaps uint64                     `json:"baseline_caps"`
	HostExposure map[string]any             `json:"host_exposure,omitempty"`
	TerminatedAt *time.Time                 `json:"terminated_at,omitempty"`
}

// Repository defines the persistence interface for runtime security events, findings, and policies.
type Repository interface {
	RegisterContainer(ctx context.Context, c ContainerRecord) error
	GetContainer(ctx context.Context, id string) (*ContainerRecord, error)
	GetContainerByCgroup(ctx context.Context, cgroupID uint64) (*ContainerRecord, error)
	RecordProcess(ctx context.Context, p security.ProcessState) error
	GetProcess(ctx context.Context, cgroupID uint64, pid uint32) (*security.ProcessState, error)
	RecordEvent(ctx context.Context, e *security.EventRecord) error
	GetTimeline(ctx context.Context, containerID string, limit int) ([]security.EventRecord, error)
	SaveFinding(ctx context.Context, f *security.Finding) error
	GetFindings(ctx context.Context, containerID string) ([]security.Finding, error)
	SetPolicy(ctx context.Context, p security.ContainerPolicy) error
	GetPolicy(ctx context.Context, containerID string) (*security.ContainerPolicy, error)
	CleanupContainer(ctx context.Context, containerID string) error
	Stats(ctx context.Context) (map[string]any, error)
}

// PostgresRepo implements Repository backed by PostgreSQL.
type PostgresRepo struct {
	db *sql.DB
}

// NewPostgresRepo constructs a PostgreSQL repository.
func NewPostgresRepo(db *sql.DB) *PostgresRepo {
	return &PostgresRepo{db: db}
}

func (r *PostgresRepo) RegisterContainer(ctx context.Context, c ContainerRecord) error {
	nsJSON, _ := json.Marshal(c.BaselineNS)
	expJSON, _ := json.Marshal(c.HostExposure)

	query := `
		INSERT INTO containers (id, cgroup_id, created_at, baseline_ns, baseline_caps, host_exposure)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (id) DO UPDATE SET
			cgroup_id = EXCLUDED.cgroup_id,
			baseline_ns = EXCLUDED.baseline_ns,
			baseline_caps = EXCLUDED.baseline_caps,
			host_exposure = EXCLUDED.host_exposure
	`
	_, err := r.db.ExecContext(ctx, query, c.ID, c.CgroupID, c.CreatedAt, nsJSON, c.BaselineCaps, expJSON)
	return err
}

func (r *PostgresRepo) GetContainer(ctx context.Context, id string) (*ContainerRecord, error) {
	query := `SELECT id, cgroup_id, created_at, baseline_ns, baseline_caps, host_exposure, terminated_at FROM containers WHERE id = $1`
	row := r.db.QueryRowContext(ctx, query, id)

	var c ContainerRecord
	var nsJSON, expJSON []byte
	err := row.Scan(&c.ID, &c.CgroupID, &c.CreatedAt, &nsJSON, &c.BaselineCaps, &expJSON, &c.TerminatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	_ = json.Unmarshal(nsJSON, &c.BaselineNS)
	_ = json.Unmarshal(expJSON, &c.HostExposure)
	return &c, nil
}

func (r *PostgresRepo) GetContainerByCgroup(ctx context.Context, cgroupID uint64) (*ContainerRecord, error) {
	query := `SELECT id, cgroup_id, created_at, baseline_ns, baseline_caps, host_exposure, terminated_at FROM containers WHERE cgroup_id = $1`
	row := r.db.QueryRowContext(ctx, query, cgroupID)

	var c ContainerRecord
	var nsJSON, expJSON []byte
	err := row.Scan(&c.ID, &c.CgroupID, &c.CreatedAt, &nsJSON, &c.BaselineCaps, &expJSON, &c.TerminatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	_ = json.Unmarshal(nsJSON, &c.BaselineNS)
	_ = json.Unmarshal(expJSON, &c.HostExposure)
	return &c, nil
}

func (r *PostgresRepo) RecordProcess(ctx context.Context, p security.ProcessState) error {
	query := `
		INSERT INTO processes (cgroup_id, pid, ppid, comm, started_at, exited_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (cgroup_id, pid, started_at) DO UPDATE SET
			comm = EXCLUDED.comm,
			exited_at = EXCLUDED.exited_at
	`
	_, err := r.db.ExecContext(ctx, query, p.CgroupID, p.PID, p.PPID, p.Comm, p.StartedAt, p.ExitedAt)
	return err
}

func (r *PostgresRepo) GetProcess(ctx context.Context, cgroupID uint64, pid uint32) (*security.ProcessState, error) {
	query := `SELECT cgroup_id, pid, ppid, comm, started_at, exited_at FROM processes WHERE cgroup_id = $1 AND pid = $2 ORDER BY started_at DESC LIMIT 1`
	row := r.db.QueryRowContext(ctx, query, cgroupID, pid)

	var p security.ProcessState
	err := row.Scan(&p.CgroupID, &p.PID, &p.PPID, &p.Comm, &p.StartedAt, &p.ExitedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &p, nil
}

func (r *PostgresRepo) RecordEvent(ctx context.Context, e *security.EventRecord) error {
	query := `
		INSERT INTO events (cgroup_id, pid, event_type, data, occurred_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id
	`
	return r.db.QueryRowContext(ctx, query, e.CgroupID, e.PID, e.Type.String(), e.Data, e.Time).Scan(&e.ID)
}

func (r *PostgresRepo) GetTimeline(ctx context.Context, containerID string, limit int) ([]security.EventRecord, error) {
	c, err := r.GetContainer(ctx, containerID)
	if err != nil {
		return nil, err
	}

	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	query := `SELECT id, occurred_at, cgroup_id, pid, event_type, data FROM events WHERE cgroup_id = $1 ORDER BY occurred_at DESC LIMIT $2`
	rows, err := r.db.QueryContext(ctx, query, c.CgroupID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []security.EventRecord
	for rows.Next() {
		var e security.EventRecord
		var typeStr string
		if err := rows.Scan(&e.ID, &e.Time, &e.CgroupID, &e.PID, &typeStr, &e.Data); err != nil {
			return nil, err
		}
		e.TypeStr = typeStr
		events = append(events, e)
	}
	return events, nil
}

func (r *PostgresRepo) SaveFinding(ctx context.Context, f *security.Finding) error {
	query := `
		INSERT INTO findings (container_id, pid, severity, finding_type, summary, event_ids, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id
	`
	return r.db.QueryRowContext(ctx, query, f.ContainerID, f.PID, string(f.Severity), f.FindingType, f.Summary, pq.Array(f.EventIDs), f.CreatedAt).Scan(&f.ID)
}

func (r *PostgresRepo) GetFindings(ctx context.Context, containerID string) ([]security.Finding, error) {
	query := `SELECT id, container_id, pid, severity, finding_type, summary, event_ids, created_at FROM findings WHERE container_id = $1 ORDER BY created_at DESC`
	rows, err := r.db.QueryContext(ctx, query, containerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []security.Finding
	for rows.Next() {
		var f security.Finding
		var sev string
		var eventIDs pq.Int64Array
		if err := rows.Scan(&f.ID, &f.ContainerID, &f.PID, &sev, &f.FindingType, &f.Summary, &eventIDs, &f.CreatedAt); err != nil {
			return nil, err
		}
		f.Severity = security.Severity(sev)
		f.EventIDs = []int64(eventIDs)
		findings = append(findings, f)
	}
	return findings, nil
}

func (r *PostgresRepo) SetPolicy(ctx context.Context, p security.ContainerPolicy) error {
	netJSON, _ := json.Marshal(p.NetworkRules)
	fsJSON, _ := json.Marshal(p.FSRules)

	query := `
		INSERT INTO policies (container_id, allowed_capabilities, network_rules, fs_rules, updated_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (container_id) DO UPDATE SET
			allowed_capabilities = EXCLUDED.allowed_capabilities,
			network_rules = EXCLUDED.network_rules,
			fs_rules = EXCLUDED.fs_rules,
			updated_at = EXCLUDED.updated_at
	`
	_, err := r.db.ExecContext(ctx, query, p.ContainerID, pq.Array(p.AllowedCapabilities), netJSON, fsJSON, time.Now())
	return err
}

func (r *PostgresRepo) GetPolicy(ctx context.Context, containerID string) (*security.ContainerPolicy, error) {
	query := `SELECT container_id, allowed_capabilities, network_rules, fs_rules, updated_at FROM policies WHERE container_id = $1`
	row := r.db.QueryRowContext(ctx, query, containerID)

	var p security.ContainerPolicy
	var caps pq.StringArray
	var netJSON, fsJSON []byte
	err := row.Scan(&p.ContainerID, &caps, &netJSON, &fsJSON, &p.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	p.AllowedCapabilities = []string(caps)
	_ = json.Unmarshal(netJSON, &p.NetworkRules)
	_ = json.Unmarshal(fsJSON, &p.FSRules)
	return &p, nil
}

func (r *PostgresRepo) CleanupContainer(ctx context.Context, containerID string) error {
	now := time.Now()
	_, err := r.db.ExecContext(ctx, `UPDATE containers SET terminated_at = $1 WHERE id = $2`, now, containerID)
	return err
}

func (r *PostgresRepo) Stats(ctx context.Context) (map[string]any, error) {
	var activeContainers, totalEvents, totalFindings int64
	_ = r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM containers WHERE terminated_at IS NULL`).Scan(&activeContainers)
	_ = r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events`).Scan(&totalEvents)
	_ = r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM findings`).Scan(&totalFindings)

	return map[string]any{
		"active_containers": activeContainers,
		"total_events":      totalEvents,
		"total_findings":    totalFindings,
	}, nil
}

// MemoryRepo is an in-memory, thread-safe implementation of Repository for testing and standalone dev.
type MemoryRepo struct {
	mu           sync.RWMutex
	containers   map[string]ContainerRecord          // keyed by container_id
	byCgroup     map[uint64]string                   // cgroup_id -> container_id
	processes    map[string]*security.ProcessState   // "cgroup:pid" -> process
	events       []security.EventRecord
	findings     map[string][]security.Finding       // container_id -> findings
	policies     map[string]security.ContainerPolicy // container_id -> policy
	eventCounter int64
	findCounter  int64
}

// NewMemoryRepo creates an in-memory repository instance.
func NewMemoryRepo() *MemoryRepo {
	return &MemoryRepo{
		containers: make(map[string]ContainerRecord),
		byCgroup:   make(map[uint64]string),
		processes:  make(map[string]*security.ProcessState),
		findings:   make(map[string][]security.Finding),
		policies:   make(map[string]security.ContainerPolicy),
	}
}

func (m *MemoryRepo) RegisterContainer(ctx context.Context, c ContainerRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.containers[c.ID] = c
	m.byCgroup[c.CgroupID] = c.ID
	return nil
}

func (m *MemoryRepo) GetContainer(ctx context.Context, id string) (*ContainerRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, exists := m.containers[id]
	if !exists {
		return nil, ErrNotFound
	}
	return &c, nil
}

func (m *MemoryRepo) GetContainerByCgroup(ctx context.Context, cgroupID uint64) (*ContainerRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, exists := m.byCgroup[cgroupID]
	if !exists {
		return nil, ErrNotFound
	}
	c := m.containers[id]
	return &c, nil
}

func (m *MemoryRepo) RecordProcess(ctx context.Context, p security.ProcessState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := fmt.Sprintf("%d:%d", p.CgroupID, p.PID)
	m.processes[key] = &p
	return nil
}

func (m *MemoryRepo) GetProcess(ctx context.Context, cgroupID uint64, pid uint32) (*security.ProcessState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := fmt.Sprintf("%d:%d", cgroupID, pid)
	p, exists := m.processes[key]
	if !exists {
		return nil, ErrNotFound
	}
	return p, nil
}

func (m *MemoryRepo) RecordEvent(ctx context.Context, e *security.EventRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e.ID = atomic.AddInt64(&m.eventCounter, 1)
	e.TypeStr = e.Type.String()
	m.events = append(m.events, *e)
	return nil
}

func (m *MemoryRepo) GetTimeline(ctx context.Context, containerID string, limit int) ([]security.EventRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	c, exists := m.containers[containerID]
	if !exists {
		return nil, ErrNotFound
	}

	var matched []security.EventRecord
	for i := len(m.events) - 1; i >= 0; i-- {
		if m.events[i].CgroupID == c.CgroupID {
			matched = append(matched, m.events[i])
			if limit > 0 && len(matched) >= limit {
				break
			}
		}
	}
	return matched, nil
}

func (m *MemoryRepo) SaveFinding(ctx context.Context, f *security.Finding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	f.ID = atomic.AddInt64(&m.findCounter, 1)
	m.findings[f.ContainerID] = append(m.findings[f.ContainerID], *f)
	return nil
}

func (m *MemoryRepo) GetFindings(ctx context.Context, containerID string) ([]security.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	list, exists := m.findings[containerID]
	if !exists {
		return []security.Finding{}, nil
	}
	return list, nil
}

func (m *MemoryRepo) SetPolicy(ctx context.Context, p security.ContainerPolicy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p.UpdatedAt = time.Now()
	m.policies[p.ContainerID] = p
	return nil
}

func (m *MemoryRepo) GetPolicy(ctx context.Context, containerID string) (*security.ContainerPolicy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, exists := m.policies[containerID]
	if !exists {
		return nil, ErrNotFound
	}
	return &p, nil
}

func (m *MemoryRepo) CleanupContainer(ctx context.Context, containerID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, exists := m.containers[containerID]; exists {
		now := time.Now()
		c.TerminatedAt = &now
		m.containers[containerID] = c
		delete(m.byCgroup, c.CgroupID)
	}
	return nil
}

func (m *MemoryRepo) Stats(ctx context.Context) (map[string]any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	active := 0
	for _, c := range m.containers {
		if c.TerminatedAt == nil {
			active++
		}
	}

	totalFindings := 0
	for _, fList := range m.findings {
		totalFindings += len(fList)
	}

	return map[string]any{
		"active_containers": active,
		"total_events":      len(m.events),
		"total_findings":    totalFindings,
	}, nil
}
