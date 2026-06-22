package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"privacyfilter/filter"
	"privacyfilter/store"
)

func newTestHandler(t *testing.T, ttl time.Duration) http.Handler {
	t.Helper()
	f, err := filter.New("../../rules/gitleaks.toml")
	if err != nil {
		t.Fatalf("filter.New: %v", err)
	}
	return HandlerWithStore(f, store.NewMemoryStore(), ttl)
}

func TestHTTPRedactReversibleAndRestoreText(t *testing.T) {
	h := newTestHandler(t, time.Minute)
	sessionID, redacted := postRedactReversible(t, h, `{"text":"邮箱 a@b.com"}`)
	if redacted != "邮箱 [邮箱_0]" {
		t.Fatalf("redacted=%q", redacted)
	}

	body := `{"session_id":"` + sessionID + `","text":"发给 [邮箱_0]"}`
	rr := postJSON(t, h, "/restore", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var out struct {
		Restored string `json:"restored"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode restore: %v", err)
	}
	if out.Restored != "发给 a@b.com" {
		t.Fatalf("restored=%q", out.Restored)
	}
}

func TestHTTPRestoreJSON(t *testing.T) {
	h := newTestHandler(t, time.Minute)
	sessionID, _ := postRedactReversible(t, h, `{"text":"邮箱 a@b.com 手机 13900001111"}`)

	body := `{"session_id":"` + sessionID + `","json":{"to":"[邮箱_0]","meta":{"phone":"[电话_0]","count":2,"ok":true,"nil":null},"list":["[邮箱_0]",3]}}`
	rr := postJSON(t, h, "/restore", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	got := rr.Body.String()
	for _, want := range []string{`"to":"a@b.com"`, `"phone":"13900001111"`, `"count":2`, `"ok":true`, `"nil":null`} {
		if !strings.Contains(got, want) {
			t.Fatalf("restore json missing %s: %s", want, got)
		}
	}
}

func TestHTTPRestoreRejectsBadRequests(t *testing.T) {
	h := newTestHandler(t, time.Minute)
	sessionID, _ := postRedactReversible(t, h, `{"text":"邮箱 a@b.com"}`)

	cases := []string{
		`{"text":"[邮箱_0]"}`,
		`{"session_id":"` + sessionID + `"}`,
		`{"session_id":"` + sessionID + `","text":"[邮箱_0]","json":{"x":"[邮箱_0]"}}`,
	}
	for _, body := range cases {
		rr := postJSON(t, h, "/restore", body)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("body=%s status=%d want 400 response=%s", body, rr.Code, rr.Body.String())
		}
	}
}

func TestHTTPRestoreMissingOrExpiredSession(t *testing.T) {
	h := newTestHandler(t, time.Nanosecond)
	sessionID, _ := postRedactReversible(t, h, `{"text":"邮箱 a@b.com"}`)
	time.Sleep(time.Millisecond)

	for _, id := range []string{"missing", sessionID} {
		body := `{"session_id":"` + id + `","text":"[邮箱_0]"}`
		rr := postJSON(t, h, "/restore", body)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("session=%s status=%d want 404 response=%s", id, rr.Code, rr.Body.String())
		}
	}
}

func postRedactReversible(t *testing.T, h http.Handler, body string) (string, string) {
	t.Helper()
	rr := postJSON(t, h, "/redact_reversible", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var out struct {
		SessionID string `json:"session_id"`
		Redacted  string `json:"redacted"`
		Mapping   map[string]string
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode redact reversible: %v", err)
	}
	if out.SessionID == "" {
		t.Fatal("session_id is empty")
	}
	if out.Mapping != nil {
		t.Fatalf("HTTP response must not expose mapping: %#v", out.Mapping)
	}
	return out.SessionID, out.Redacted
}

func postJSON(t *testing.T, h http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}
