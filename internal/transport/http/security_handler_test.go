package http

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labib0x9/docpine/internal/app/security"
	domainsec "github.com/labib0x9/docpine/internal/domain/security"
	"github.com/labib0x9/docpine/internal/infra/postgres"
)

func TestSecurityHandler_Endpoints(t *testing.T) {
	ctx := context.Background()
	repo := postgres.NewMemoryRepo()
	engine := security.NewEngine(repo)

	containerID := "test-container-http"
	cgroupID := uint64(1234)

	_ = engine.RegisterContainer(ctx, containerID, cgroupID, "docker", domainsec.NamespaceIdentity{}, domainsec.CAP_CHOWN, nil)

	handler := NewSecurityHandler(engine)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// 1. Ingest simulated shell-to-exfil sequence
	now := time.Now()
	events := []domainsec.EventRecord{
		{Time: now, CgroupID: cgroupID, PID: 50, Type: domainsec.EventExec, Comm: "sh", Data: "/bin/sh"},
		{Time: now.Add(10 * time.Millisecond), CgroupID: cgroupID, PID: 50, Type: domainsec.EventOpenat, Comm: "cat", Data: "/etc/shadow"},
		{Time: now.Add(20 * time.Millisecond), CgroupID: cgroupID, PID: 50, Type: domainsec.EventConnect, Comm: "curl", Data: "203.0.113.10:443"},
	}

	for _, ev := range events {
		evJSON, _ := json.Marshal(ev)
		req := httptest.NewRequest(http.MethodPost, "/security/events/simulate", bytes.NewReader(evJSON))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected HTTP 200 on simulate event, got %d", w.Code)
		}
	}

	// 2. GET /containers/{id}/findings
	reqFindings := httptest.NewRequest(http.MethodGet, "/containers/"+containerID+"/findings", nil)
	wFindings := httptest.NewRecorder()
	mux.ServeHTTP(wFindings, reqFindings)

	if wFindings.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 for findings, got %d", wFindings.Code)
	}

	var findingsResp map[string]any
	if err := json.Unmarshal(wFindings.Body.Bytes(), &findingsResp); err != nil {
		t.Fatalf("failed to decode findings JSON: %v", err)
	}

	count, ok := findingsResp["count"].(float64)
	if !ok || count < 1 {
		t.Fatalf("expected at least 1 finding in response, got %v", findingsResp)
	}

	// 3. GET /containers/{id}/timeline
	reqTimeline := httptest.NewRequest(http.MethodGet, "/containers/"+containerID+"/timeline", nil)
	wTimeline := httptest.NewRecorder()
	mux.ServeHTTP(wTimeline, reqTimeline)

	if wTimeline.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 for timeline, got %d", wTimeline.Code)
	}

	// 4. POST /containers/{id}/policy
	policyPayload := domainsec.ContainerPolicy{
		AllowedCapabilities: []string{"CAP_CHOWN"},
		NetworkRules: []domainsec.NetworkRule{
			{DstIP: "0.0.0.0", DstPort: 443, Action: "deny"},
		},
	}
	polJSON, _ := json.Marshal(policyPayload)
	reqPolicy := httptest.NewRequest(http.MethodPost, "/containers/"+containerID+"/policy", bytes.NewReader(polJSON))
	wPolicy := httptest.NewRecorder()
	mux.ServeHTTP(wPolicy, reqPolicy)

	if wPolicy.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 on set policy, got %d", wPolicy.Code)
	}

	// 5. GET /containers/{id}/policy
	reqGetPolicy := httptest.NewRequest(http.MethodGet, "/containers/"+containerID+"/policy", nil)
	wGetPolicy := httptest.NewRecorder()
	mux.ServeHTTP(wGetPolicy, reqGetPolicy)

	if wGetPolicy.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 on get policy, got %d", wGetPolicy.Code)
	}

	// 6. GET /security/stats
	reqStats := httptest.NewRequest(http.MethodGet, "/security/stats", nil)
	wStats := httptest.NewRecorder()
	mux.ServeHTTP(wStats, reqStats)

	if wStats.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 for stats, got %d", wStats.Code)
	}
}
