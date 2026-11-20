package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"hijackwatch/internal/detect"
	"hijackwatch/internal/model"
	"hijackwatch/internal/policy"
)

func testServer() *Server {
	cfg := policy.Defaults()
	cfg.Prefixes = []policy.Prefix{
		{CIDR: "203.0.113.0/24", ExpectedOrigins: []uint32{133900}, ApprovedCleanings: []uint32{129900}},
	}
	cfg.MinAlertSeverity = model.SevLow
	cfg.NeighborRTT = time.Minute
	return New(detect.New(cfg))
}

func TestIngestAndQuery(t *testing.T) {
	s := testServer()
	now := time.Now().UTC()

	body, _ := json.Marshal(model.Update{
		Collector: "c1", PeerASN: 65001, Type: model.Announce, Prefix: "203.0.113.0/24",
		ASPath: []uint32{65001, 129000, 204500}, EventTime: now.Add(-time.Minute), ReceivedAt: now,
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/updates", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("ingest status = %d, body %s", rec.Code, rec.Body)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/stats", nil)
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	var statsResp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &statsResp); err != nil {
		t.Fatalf("stats json: %v", err)
	}
	stats, _ := statsResp["stats"].(map[string]any)
	if stats["Received"].(float64) != 1 {
		t.Errorf("Received = %v, want 1", stats["Received"])
	}
}

func TestIngestRejectsInvalid(t *testing.T) {
	s := testServer()
	req := httptest.NewRequest(http.MethodPost, "/v1/updates", bytes.NewReader([]byte(`{"collector":"","type":"announce"}`)))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity && rec.Code != http.StatusBadRequest {
		t.Errorf("invalid update status = %d", rec.Code)
	}
}

func TestAlertsEndpoint(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/alerts?min_severity=high", nil)
	rec := httptest.NewRecorder()
	testServer().Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("alerts status = %d", rec.Code)
	}
	var resp struct {
		Count  int           `json:"count"`
		Alerts []model.Alert `json:"alerts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("alerts json: %v", err)
	}
}

func TestAlertNotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/alerts/nope", nil)
	rec := httptest.NewRecorder()
	testServer().Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("missing alert status = %d, want 404", rec.Code)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	testServer().Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics status = %d", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("bgpwatch_updates_total")) {
		t.Error("metrics missing bgpwatch_updates_total")
	}
}

func TestDashboardRenders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	testServer().Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("dashboard status = %d", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("hijackwatch")) {
		t.Error("dashboard missing header")
	}
}

func TestHealthz(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	testServer().Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("healthz status = %d", rec.Code)
	}
}
