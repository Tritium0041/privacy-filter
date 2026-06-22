package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"privacyfilter/filter"
)

func TestGatewayRedactsRequestAndRestoresResponse(t *testing.T) {
	var upstreamBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read upstream body: %v", err)
		}
		upstreamBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"sent to [邮箱_0]"}`))
	}))
	defer upstream.Close()

	h := newTestGateway(t, upstream.URL)
	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/chat", strings.NewReader(`{"prompt":"发邮件给 a@b.com"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(upstreamBody, "[邮箱_0]") || strings.Contains(upstreamBody, "a@b.com") {
		t.Fatalf("upstream did not receive redacted body: %s", upstreamBody)
	}
	if got := rr.Body.String(); got != `{"message":"sent to a@b.com"}` {
		t.Fatalf("client response=%s", got)
	}
}

func TestGatewayRewritesHostAndDoesNotDoubleBasePath(t *testing.T) {
	var upstreamHost, upstreamPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHost = r.Host
		upstreamPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"ok"}`))
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL + "/v1")
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	f, err := filter.New("../../rules/gitleaks.toml")
	if err != nil {
		t.Fatalf("filter.New: %v", err)
	}
	h := NewWithOptions(f, upstreamURL, Options{Logger: log.New(io.Discard, "", 0)})
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8090/v1/models", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if upstreamHost != upstreamURL.Host {
		t.Fatalf("upstream Host=%q want %q", upstreamHost, upstreamURL.Host)
	}
	if upstreamPath != "/v1/models" {
		t.Fatalf("upstream path=%q want /v1/models", upstreamPath)
	}
}

func TestGatewayPreservesJSONRequestBytesWhenNoHit(t *testing.T) {
	var upstreamBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read upstream body: %v", err)
		}
		upstreamBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"ok"}`))
	}))
	defer upstream.Close()

	h := newTestGateway(t, upstream.URL)
	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/v1/responses", strings.NewReader(`{"input":"你好","stream":true}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if upstreamBody != `{"input":"你好","stream":true}` {
		t.Fatalf("request body changed unexpectedly: %s", upstreamBody)
	}
}

func TestGatewayRedactsJSONRequestByOriginalReplacement(t *testing.T) {
	var upstreamBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read upstream body: %v", err)
		}
		upstreamBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"sent to [邮箱_0]"}`))
	}))
	defer upstream.Close()

	h := newTestGateway(t, upstream.URL)
	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/v1/responses", strings.NewReader(`{"input":"发邮件给 a@b.com","stream":true}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if upstreamBody != `{"input":"发邮件给 [邮箱_0]","stream":true}` {
		t.Fatalf("request body not redacted by original replacement: %s", upstreamBody)
	}
	if got := rr.Body.String(); got != `{"message":"sent to a@b.com"}` {
		t.Fatalf("client response=%s", got)
	}
}

func TestGatewayBypassesCodexSessionAfterMarker(t *testing.T) {
	var upstreamBodies []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read upstream body: %v", err)
		}
		upstreamBodies = append(upstreamBodies, string(body))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"sent to [邮箱_0]"}`))
	}))
	defer upstream.Close()

	var logs bytes.Buffer
	h := newTestGatewayWithOptions(t, upstream.URL, Options{
		Logger:       log.New(&logs, "", 0),
		LogLevel:     LogLevelDebug,
		BypassMarker: "privacy-filter-bypass",
	})

	firstBody := `{"session_id":"codex-session-123","input":"privacy-filter-bypass 发邮件给 a@b.com"}`
	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/v1/responses", strings.NewReader(firstBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("first status=%d body=%s", rr.Code, rr.Body.String())
	}
	if len(upstreamBodies) != 1 || upstreamBodies[0] != firstBody {
		t.Fatalf("marker request should bypass redaction, got %#v", upstreamBodies)
	}
	if got := rr.Body.String(); got != `{"message":"sent to [邮箱_0]"}` {
		t.Fatalf("bypassed request should not restore response placeholders: %s", got)
	}

	secondBody := `{"session_id":"codex-session-123","input":"发邮件给 c@d.com"}`
	req = httptest.NewRequest(http.MethodPost, "http://gateway.local/v1/responses", strings.NewReader(secondBody))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("second status=%d body=%s", rr.Code, rr.Body.String())
	}
	if len(upstreamBodies) != 2 || upstreamBodies[1] != secondBody {
		t.Fatalf("same session should continue bypassing redaction, got %#v", upstreamBodies)
	}
	gotLogs := logs.String()
	for _, want := range []string{
		`event="request_bypass"`,
		`reason="marker"`,
		`reason="session"`,
		`session_hash=`,
	} {
		if !strings.Contains(gotLogs, want) {
			t.Fatalf("bypass logs missing %q:\n%s", want, gotLogs)
		}
	}
	if strings.Contains(gotLogs, "codex-session-123") {
		t.Fatalf("bypass logs should not include raw session id:\n%s", gotLogs)
	}
}

func TestGatewayBypassMarkerRequiresCodexSession(t *testing.T) {
	var upstreamBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read upstream body: %v", err)
		}
		upstreamBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"sent to [邮箱_0]"}`))
	}))
	defer upstream.Close()

	h := newTestGatewayWithOptions(t, upstream.URL, Options{
		Logger:       log.New(io.Discard, "", 0),
		BypassMarker: "privacy-filter-bypass",
	})
	body := `{"session_id":"business-session","input":"privacy-filter-bypass 发邮件给 a@b.com"}`
	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/v1/responses", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if upstreamBody != `{"session_id":"business-session","input":"privacy-filter-bypass 发邮件给 [邮箱_0]"}` {
		t.Fatalf("marker without codex session should still redact: %s", upstreamBody)
	}
	if got := rr.Body.String(); got != `{"message":"sent to a@b.com"}` {
		t.Fatalf("non-bypassed response should restore placeholders: %s", got)
	}
}

func TestGatewayDoesNotRedactResponsesControlJSON(t *testing.T) {
	var upstreamBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read upstream body: %v", err)
		}
		upstreamBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"ok"}`))
	}))
	defer upstream.Close()

	body := `{"model":"gpt-5.4-mini","input":"你好","store":false,"stream":true,"include":["reasoning.encrypted_content"],"reasoning":{"effort":"low"},"text":{"verbosity":"medium","format":{"type":"json_schema","strict":true,"schema":{"type":"object","properties":{"rollout_summary":{"type":"string"}},"required":["rollout_summary"],"additionalProperties":false},"name":"codex_output_schema"}}}`
	h := newTestGateway(t, upstream.URL)
	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/v1/responses", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if err := json.Unmarshal([]byte(upstreamBody), new(any)); err != nil {
		t.Fatalf("redacted request is invalid JSON: %v\n%s", err, upstreamBody)
	}
	if strings.Contains(upstreamBody, "[密钥_") {
		t.Fatalf("control JSON should not be redacted: %s", upstreamBody)
	}
}

func TestGatewayDoesNotRedactResponsesProtocolIDs(t *testing.T) {
	var upstreamBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read upstream body: %v", err)
		}
		upstreamBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"sent to [邮箱_0]"}`))
	}))
	defer upstream.Close()

	callID := "call_UF2qV5FnFjz1lPb87HUyEDoN"
	responseID := "resp_abcDEF1234567890xyzUVW"
	messageID := "msg_abcDEF1234567890xyzUVW"
	body := `{"model":"gpt-5.5","previous_response_id":` + strconv.Quote(responseID) +
		`,"input":[{"id":` + strconv.Quote(messageID) +
		`,"type":"function_call_output","call_id":` + strconv.Quote(callID) +
		`,"output":"发邮件给 a@b.com"}],"stream":true}`
	h := newTestGateway(t, upstream.URL)
	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/v1/responses", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if err := json.Unmarshal([]byte(upstreamBody), new(any)); err != nil {
		t.Fatalf("redacted request is invalid JSON: %v\n%s", err, upstreamBody)
	}
	for _, want := range []string{callID, responseID, messageID} {
		if !strings.Contains(upstreamBody, strconv.Quote(want)) {
			t.Fatalf("protocol id %q should remain unchanged: %s", want, upstreamBody)
		}
	}
	if !strings.Contains(upstreamBody, `"output":"发邮件给 [邮箱_0]"`) {
		t.Fatalf("normal output text should still be redacted: %s", upstreamBody)
	}
	if strings.Contains(upstreamBody, "[密钥_") {
		t.Fatalf("protocol ids should not become secret placeholders: %s", upstreamBody)
	}
	if got := rr.Body.String(); got != `{"message":"sent to a@b.com"}` {
		t.Fatalf("client response=%s", got)
	}
}

func TestGatewayStillRedactsNonProtocolIDFieldValues(t *testing.T) {
	var upstreamBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read upstream body: %v", err)
		}
		upstreamBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"sent to [邮箱_0]"}`))
	}))
	defer upstream.Close()

	body := `{"id":"a@b.com","input":"hello"}`
	h := newTestGateway(t, upstream.URL)
	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/v1/responses", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if upstreamBody != `{"id":"[邮箱_0]","input":"hello"}` {
		t.Fatalf("non-protocol id value should still be redacted: %s", upstreamBody)
	}
}

func TestGatewayDoesNotRedactEscapedExistingPlaceholder(t *testing.T) {
	var upstreamBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read upstream body: %v", err)
		}
		upstreamBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"ok"}`))
	}))
	defer upstream.Close()

	body := `{"input":"token: [密钥]\" still inside JSON string"}`
	h := newTestGateway(t, upstream.URL)
	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/v1/responses", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if upstreamBody != body {
		t.Fatalf("escaped placeholder should remain unchanged:\n%s", upstreamBody)
	}
	if err := json.Unmarshal([]byte(upstreamBody), new(any)); err != nil {
		t.Fatalf("request body should remain valid JSON: %v\n%s", err, upstreamBody)
	}
}

func TestGatewayWithEntropyFallbackDisabledDoesNotRedactEntropyOnlyText(t *testing.T) {
	var upstreamBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read upstream body: %v", err)
		}
		upstreamBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"ok"}`))
	}))
	defer upstream.Close()

	f, err := filter.NewWithOptions("../../rules/gitleaks.toml", filter.Options{DisableEntropyFallback: true})
	if err != nil {
		t.Fatalf("filter.NewWithOptions: %v", err)
	}
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	h := NewWithOptions(f, upstreamURL, Options{Logger: log.New(io.Discard, "", 0)})
	body := `{"input":"TestEntropyFallbackSkipsFilesystemPath /rollout_summaries/2026-06-10T13-36-11-FDHV-agent_scratch_tui_token_usage_and_compact_command"}`
	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/v1/responses", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if upstreamBody != body {
		t.Fatalf("entropy-only text should remain unchanged:\n%s", upstreamBody)
	}
	if strings.Contains(upstreamBody, "[密钥_") {
		t.Fatalf("entropy-only text should not contain secret placeholders: %s", upstreamBody)
	}
}

func TestGatewayDoesNotRedactLargeToolOutputAsSecret(t *testing.T) {
	var upstreamBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read upstream body: %v", err)
		}
		upstreamBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"ok"}`))
	}))
	defer upstream.Close()

	toolOutput := strings.Repeat("PRIVATE KEY note: this is only documentation inside tool output, not a PEM block. ", 80)
	body := `{"model":"gpt-5.5","input":[{"type":"function_call_output","call_id":"call_1","output":` +
		strconv.Quote(toolOutput) +
		`}],"stream":true}`
	h := newTestGateway(t, upstream.URL)
	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/v1/responses", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if err := json.Unmarshal([]byte(upstreamBody), new(any)); err != nil {
		t.Fatalf("redacted request is invalid JSON: %v\n%s", err, upstreamBody)
	}
	if upstreamBody != body {
		t.Fatalf("tool output request should remain unchanged:\n%s", upstreamBody)
	}
	if strings.Contains(upstreamBody, "[密钥_") {
		t.Fatalf("tool output should not contain secret placeholders: %s", upstreamBody)
	}
}

func TestGatewayDoesNotRedactEncryptedContent(t *testing.T) {
	var upstreamBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read upstream body: %v", err)
		}
		upstreamBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"sent to [邮箱_0]"}`))
	}))
	defer upstream.Close()

	encrypted := `opaque 13900001111 192.168.1.10 token=aB3xK9pLmN2qR7sT5vW1zY`
	body := `{"model":"gpt-5.5","input":"发邮件给 a@b.com","include":["reasoning.encrypted_content"],"reasoning":{"encrypted_content":` +
		strconv.Quote(encrypted) +
		`},"output":[{"content":[{"encrypted_content":` +
		strconv.Quote(encrypted) +
		`}]}],"stream":true}`
	h := newTestGateway(t, upstream.URL)
	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/v1/responses", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if err := json.Unmarshal([]byte(upstreamBody), new(any)); err != nil {
		t.Fatalf("redacted request is invalid JSON: %v\n%s", err, upstreamBody)
	}
	if !strings.Contains(upstreamBody, `"input":"发邮件给 [邮箱_0]"`) {
		t.Fatalf("normal input should still be redacted: %s", upstreamBody)
	}
	if strings.Count(upstreamBody, strconv.Quote(encrypted)) != 2 {
		t.Fatalf("encrypted_content should remain unchanged: %s", upstreamBody)
	}
	if strings.Contains(upstreamBody, "[电话_") || strings.Contains(upstreamBody, "[IP_") || strings.Contains(upstreamBody, "[密钥_") {
		t.Fatalf("encrypted_content should not contain placeholders: %s", upstreamBody)
	}
}

func TestGatewayLogsReplacementAndRestoreDetails(t *testing.T) {
	var logs bytes.Buffer
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"sent to [邮箱_0]"}`))
	}))
	defer upstream.Close()

	h := newTestGatewayWithOptions(t, upstream.URL, Options{
		Logger:   log.New(&logs, "", 0),
		LogLevel: LogLevelDebug,
	})
	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/chat", strings.NewReader(`{"prompt":"发邮件给 a@b.com"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", "test-req-1")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	got := logs.String()
	for _, want := range []string{
		`event="request_start"`,
		`request_id="test-req-1"`,
		`event="request_redact"`,
		`placeholder\":\"[邮箱_0]`,
		`event="request_replace"`,
		`type="[邮箱]"`,
		`placeholder="[邮箱_0]"`,
		`original="a@b.com"`,
		`event="response_restore_body"`,
		`placeholder_hits=1`,
		`event="response_restore"`,
		`mode="json"`,
		`count=1`,
		`event="request_complete"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("logs missing %q:\n%s", want, got)
		}
	}
	if rr.Header().Get("X-Privacy-Gateway-Request-ID") != "test-req-1" {
		t.Fatalf("missing response request id header: %q", rr.Header().Get("X-Privacy-Gateway-Request-ID"))
	}
}

func TestGatewayDebugBodyLogsTruncatedRedactedBody(t *testing.T) {
	var logs bytes.Buffer
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"ok [邮箱_0]"}`))
	}))
	defer upstream.Close()

	h := newTestGatewayWithOptions(t, upstream.URL, Options{
		Logger:          log.New(&logs, "", 0),
		LogLevel:        LogLevelDebug,
		DebugBody:       true,
		MaxBodyLogBytes: 24,
	})
	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/chat", strings.NewReader(`{"prompt":"发邮件给 a@b.com 并附带一段很长很长的上下文"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	got := logs.String()
	if !strings.Contains(got, `event="request_body_redacted"`) || !strings.Contains(got, `truncated=true`) {
		t.Fatalf("debug body log missing or not truncated:\n%s", got)
	}
	if !strings.Contains(got, `event="response_body_restored"`) || !strings.Contains(got, "a@b.com") {
		t.Fatalf("debug response body log should include restored body for explicit debugging:\n%s", got)
	}
}

func TestGatewayDebugBodyLogsRespectLogLevel(t *testing.T) {
	var logs bytes.Buffer
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"ok [邮箱_0]"}`))
	}))
	defer upstream.Close()

	h := newTestGatewayWithOptions(t, upstream.URL, Options{
		Logger:    log.New(&logs, "", 0),
		LogLevel:  LogLevelInfo,
		DebugBody: true,
	})
	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/chat", strings.NewReader(`{"prompt":"发邮件给 a@b.com"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	got := logs.String()
	if strings.Contains(got, `level=debug`) ||
		strings.Contains(got, `event="request_body_redacted"`) ||
		strings.Contains(got, `event="response_body_restored"`) {
		t.Fatalf("info log level should not include debug body logs:\n%s", got)
	}
	if !strings.Contains(got, `event="request_replace"`) || !strings.Contains(got, `event="response_restore"`) {
		t.Fatalf("info detail logs should still be present:\n%s", got)
	}
}

func TestGatewayLeavesResponseWithoutMappingAlone(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"ok"}`))
	}))
	defer upstream.Close()

	h := newTestGateway(t, upstream.URL)
	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/chat", strings.NewReader(`{"prompt":"hello"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Body.String(); got != `{"message":"ok"}` {
		t.Fatalf("client response=%s", got)
	}
}

func TestGatewayRestoresResponsesAPIStreamAcrossDeltas(t *testing.T) {
	var logs bytes.Buffer
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		events := []string{
			"event: response.output_text.delta\n" +
				`data: {"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"sent to ["}` + "\n\n",
			"event: response.output_text.delta\n" +
				`data: {"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"邮箱_"}` + "\n\n",
			"event: response.output_text.delta\n" +
				`data: {"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"0] now"}` + "\n\n",
			"event: response.completed\n" +
				`data: {"type":"response.completed","response":{"output_text":"sent to [邮箱_0] now"}}` + "\n\n",
		}
		for _, event := range events {
			_, _ = w.Write([]byte(event))
		}
	}))
	defer upstream.Close()

	h := newTestGatewayWithOptions(t, upstream.URL, Options{
		Logger:   log.New(&logs, "", 0),
		LogLevel: LogLevelInfo,
	})
	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/v1/responses", strings.NewReader(`{"input":"发邮件给 a@b.com","stream":true}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var combined string
	for _, line := range strings.Split(rr.Body.String(), "\n") {
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &payload); err != nil {
			t.Fatalf("decode SSE payload: %v\nbody=%s", err, rr.Body.String())
		}
		if delta, ok := payload["delta"].(string); ok {
			combined += delta
		}
	}
	if combined != "sent to a@b.com now" {
		t.Fatalf("combined stream=%q body=%s", combined, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"output_text":"sent to a@b.com now"`) {
		t.Fatalf("completed event was not restored: %s", rr.Body.String())
	}
	gotLogs := logs.String()
	for _, want := range []string{
		`event="response_restore"`,
		`mode="sse"`,
		`placeholder="[邮箱_0]"`,
		`original="a@b.com"`,
		`count=2`,
		`event="response_restore_sse_complete"`,
		`placeholder_hits=2`,
	} {
		if !strings.Contains(gotLogs, want) {
			t.Fatalf("SSE logs missing %q:\n%s", want, gotLogs)
		}
	}
}

func TestGatewayRestoresFunctionCallArgumentsDeltas(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		events := []string{
			"event: response.function_call_arguments.delta\n" +
				`data: {"type":"response.function_call_arguments.delta","item_id":"call_1","delta":"{\"to\":\"["}` + "\n\n",
			"event: response.function_call_arguments.delta\n" +
				`data: {"type":"response.function_call_arguments.delta","item_id":"call_1","delta":"邮箱_"}` + "\n\n",
			"event: response.function_call_arguments.delta\n" +
				`data: {"type":"response.function_call_arguments.delta","item_id":"call_1","delta":"0]\"}"}` + "\n\n",
		}
		for _, event := range events {
			_, _ = w.Write([]byte(event))
		}
	}))
	defer upstream.Close()

	h := newTestGateway(t, upstream.URL)
	req := httptest.NewRequest(http.MethodPost, "http://gateway.local/v1/responses", strings.NewReader(`{"input":"发邮件给 a@b.com","stream":true}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var combined string
	for _, line := range strings.Split(rr.Body.String(), "\n") {
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &payload); err != nil {
			t.Fatalf("decode SSE payload: %v\nbody=%s", err, rr.Body.String())
		}
		if delta, ok := payload["delta"].(string); ok {
			combined += delta
		}
	}
	if combined != `{"to":"a@b.com"}` {
		t.Fatalf("combined arguments=%q body=%s", combined, rr.Body.String())
	}
}

func newTestGateway(t *testing.T, upstreamRawURL string) http.Handler {
	return newTestGatewayWithOptions(t, upstreamRawURL, Options{Logger: log.New(io.Discard, "", 0)})
}

func newTestGatewayWithOptions(t *testing.T, upstreamRawURL string, opts Options) http.Handler {
	t.Helper()
	f, err := filter.New("../../rules/gitleaks.toml")
	if err != nil {
		t.Fatalf("filter.New: %v", err)
	}
	upstreamURL, err := url.Parse(upstreamRawURL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	return NewWithOptions(f, upstreamURL, opts)
}
