// Package httpapi 把 *filter.Filter 包成 HTTP REST 接口。
package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"privacyfilter/filter"
	"privacyfilter/store"
)

type redactRequest struct {
	Text string `json:"text"`
}

type restoreRequest struct {
	SessionID string           `json:"session_id"`
	Text      *string          `json:"text,omitempty"`
	JSON      *json.RawMessage `json:"json,omitempty"`
}

type batchRequest struct {
	Texts []string `json:"texts"`
}

// redactResponse = filter.Result + 耗时。
type redactResponse struct {
	filter.Result
	ElapsedMs float64 `json:"elapsed_ms"`
}

type reversibleResponse struct {
	filter.Result
	ElapsedMs float64 `json:"elapsed_ms"`
	SessionID string  `json:"session_id"`
}

type restoreTextResponse struct {
	Restored string `json:"restored"`
}

type restoreJSONResponse struct {
	JSON any `json:"json"`
}

// Handler 返回一个已注册 /health、/redact、/redact/batch 的 http.Handler。
// 多个 cmd 共用，避免重复实现。
func Handler(f *filter.Filter) http.Handler {
	return HandlerWithStore(f, store.NewMemoryStore(), store.DefaultTTL)
}

// HandlerWithStore 返回 HTTP handler，并额外启用可逆脱敏与还原接口。
func HandlerWithStore(f *filter.Filter, sessions store.SessionStore, ttl time.Duration) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		rules, skipped := f.Stats()
		writeJSON(w, http.StatusOK, map[string]any{
			"status":         "ok",
			"gitleaks_rules": rules,
			"skipped_rules":  skipped,
		})
	})
	mux.HandleFunc("POST /redact", func(w http.ResponseWriter, r *http.Request) {
		var req redactRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, redactOne(f, req.Text))
	})
	mux.HandleFunc("POST /redact_reversible", func(w http.ResponseWriter, r *http.Request) {
		var req redactRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		out, err := redactReversible(f, sessions, ttl, req.Text)
		if err != nil {
			http.Error(w, "save session failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("POST /restore", func(w http.ResponseWriter, r *http.Request) {
		var req restoreRequest
		dec := json.NewDecoder(r.Body)
		dec.UseNumber()
		if err := dec.Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if req.SessionID == "" {
			http.Error(w, "session_id is required", http.StatusBadRequest)
			return
		}
		if (req.Text == nil && req.JSON == nil) || (req.Text != nil && req.JSON != nil) {
			http.Error(w, "exactly one of text or json is required", http.StatusBadRequest)
			return
		}
		mapping, err := sessions.Load(req.SessionID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrExpired) {
				http.Error(w, "session not found", http.StatusNotFound)
				return
			}
			http.Error(w, "load session failed", http.StatusInternalServerError)
			return
		}
		if req.Text != nil {
			writeJSON(w, http.StatusOK, restoreTextResponse{Restored: filter.RestoreText(*req.Text, mapping)})
			return
		}

		var payload any
		jsonDec := json.NewDecoder(bytes.NewReader(*req.JSON))
		jsonDec.UseNumber()
		if err := jsonDec.Decode(&payload); err != nil {
			http.Error(w, "invalid json payload", http.StatusBadRequest)
			return
		}
		restored, err := filter.RestoreJSON(payload, mapping)
		if err != nil {
			http.Error(w, "invalid json payload", http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, restoreJSONResponse{JSON: restored})
	})
	mux.HandleFunc("POST /redact/batch", func(w http.ResponseWriter, r *http.Request) {
		var req batchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		out := make([]redactResponse, len(req.Texts))
		for i, t := range req.Texts {
			out[i] = redactOne(f, t)
		}
		writeJSON(w, http.StatusOK, out)
	})
	return mux
}

func redactOne(f *filter.Filter, text string) redactResponse {
	t0 := time.Now()
	res := f.Redact(text)
	return redactResponse{
		Result:    res,
		ElapsedMs: float64(time.Since(t0).Microseconds()) / 1000.0,
	}
}

func redactReversible(f *filter.Filter, sessions store.SessionStore, ttl time.Duration, text string) (reversibleResponse, error) {
	t0 := time.Now()
	res := f.RedactReversible(text)
	sessionID, err := sessions.Save(res.Mapping, ttl)
	if err != nil {
		return reversibleResponse{}, err
	}
	return reversibleResponse{
		Result:    res.Result,
		ElapsedMs: float64(time.Since(t0).Microseconds()) / 1000.0,
		SessionID: sessionID,
	}, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}
