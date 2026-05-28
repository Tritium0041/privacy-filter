// Package httpapi 把 *filter.Filter 包成 HTTP REST 接口。
package httpapi

import (
	"encoding/json"
	"net/http"
	"time"

	"privacyfilter/filter"
)

type redactRequest struct {
	Text string `json:"text"`
}

type batchRequest struct {
	Texts []string `json:"texts"`
}

// redactResponse = filter.Result + 耗时。
type redactResponse struct {
	filter.Result
	ElapsedMs float64 `json:"elapsed_ms"`
}

// Handler 返回一个已注册 /health、/redact、/redact/batch 的 http.Handler。
// 多个 cmd 共用，避免重复实现。
func Handler(f *filter.Filter) http.Handler {
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}
