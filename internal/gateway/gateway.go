// Package gateway 提供一个示例反向代理：请求进上游前可逆脱敏，
// 上游响应回来后按本次请求的映射自动还原占位符。
package gateway

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"privacyfilter/filter"
)

// Gateway 是一个带隐私过滤能力的反向代理。
type Gateway struct {
	f               *filter.Filter
	proxy           *httputil.ReverseProxy
	logger          *log.Logger
	logLevel        LogLevel
	debugBody       bool
	maxBodyLogBytes int
	bypass          bypassSessions
}

type mappingContextKey struct{}
type requestLogContextKey struct{}

const (
	defaultMaxBodyLogBytes   = 4096
	defaultMaxBypassSessions = 1024
	requestIDHeader          = "X-Request-ID"
	gatewayRequestIDHeader   = "X-Privacy-Gateway-Request-ID"
)

var codexSessionIDFields = []string{
	"session_id",
	"codex_session_id",
	"conversation_id",
	"thread_id",
}

var codexSessionIDHeaders = []string{
	"X-Codex-Session-ID",
	"Codex-Session-ID",
	"X-Session-ID",
}

var protectedRequestJSONFields = []string{
	"encrypted_content",
	"id",
	"session_id",
	"codex_session_id",
	"previous_response_id",
	"tool_call_id",
	"call_id",
	"item_id",
	"output_item_id",
	"response_id",
	"conversation_id",
	"thread_id",
	"run_id",
	"step_id",
	"assistant_id",
	"file_id",
	"batch_id",
}

// LogLevel controls gateway log verbosity.
type LogLevel int

const (
	LogLevelDefault LogLevel = iota
	LogLevelError
	LogLevelInfo
	LogLevelDebug
	LogLevelTrace
)

func (l LogLevel) String() string {
	switch l {
	case LogLevelError:
		return "error"
	case LogLevelInfo:
		return "info"
	case LogLevelDebug:
		return "debug"
	case LogLevelTrace:
		return "trace"
	default:
		return "default"
	}
}

// ParseLogLevel parses error, info, debug, or trace.
func ParseLogLevel(value string) (LogLevel, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "info":
		return LogLevelInfo, nil
	case "error":
		return LogLevelError, nil
	case "debug":
		return LogLevelDebug, nil
	case "trace":
		return LogLevelTrace, nil
	default:
		return LogLevelDefault, fmt.Errorf("invalid log level %q (want error, info, debug, or trace)", value)
	}
}

// New 创建一个代理到 upstream 的示例网关。
func New(f *filter.Filter, upstream *url.URL) *Gateway {
	return NewWithOptions(f, upstream, Options{})
}

type Options struct {
	Logger          *log.Logger
	LogLevel        LogLevel
	DebugBody       bool
	MaxBodyLogBytes int
	BypassMarker    string
}

// NewWithOptions 创建一个可配置的示例网关。
func NewWithOptions(f *filter.Filter, upstream *url.URL, opts Options) *Gateway {
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	g := &Gateway{
		f:               f,
		proxy:           proxy,
		logger:          opts.Logger,
		logLevel:        normalizeLogLevel(opts.LogLevel),
		debugBody:       opts.DebugBody,
		maxBodyLogBytes: opts.MaxBodyLogBytes,
		bypass:          newBypassSessions(opts.BypassMarker, defaultMaxBypassSessions),
	}
	if g.logger == nil {
		g.logger = log.Default()
	}
	if g.maxBodyLogBytes <= 0 {
		g.maxBodyLogBytes = defaultMaxBodyLogBytes
	}
	originalDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		originalPath := r.URL.EscapedPath()
		originalRawPath := r.URL.RawPath
		originalDirector(r)
		r.Host = upstream.Host
		r.URL.Path = gatewayUpstreamPath(upstream.EscapedPath(), originalPath)
		if rawPath := gatewayUpstreamPath(upstream.RawPath, originalRawPath); rawPath != "" {
			r.URL.RawPath = rawPath
		}
		// 让示例网关拿到明文响应体，便于自动还原占位符。
		r.Header.Del("Accept-Encoding")
		g.logEvent(LogLevelDebug, requestIDFromContext(r.Context()), "upstream_request",
			"method", r.Method,
			"scheme", r.URL.Scheme,
			"host", r.URL.Host,
			"path", r.URL.EscapedPath(),
			"query_present", r.URL.RawQuery != "",
			"content_length", r.ContentLength,
		)
	}
	proxy.ModifyResponse = g.restoreResponse
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		g.logEvent(LogLevelError, requestIDFromRequest(r), "proxy_error", "error", err.Error())
		http.Error(w, "upstream proxy error", http.StatusBadGateway)
	}
	return g
}

func gatewayUpstreamPath(basePath, reqPath string) string {
	if basePath == "" || basePath == "/" {
		return reqPath
	}
	if reqPath == "" || reqPath == "/" {
		return basePath
	}
	if reqPath == basePath || strings.HasPrefix(reqPath, strings.TrimRight(basePath, "/")+"/") {
		return reqPath
	}
	return strings.TrimRight(basePath, "/") + "/" + strings.TrimLeft(reqPath, "/")
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFor(r)
	start := time.Now()
	w.Header().Set(gatewayRequestIDHeader, requestID)
	if r.Header.Get(requestIDHeader) == "" {
		r.Header.Set(requestIDHeader, requestID)
	}
	r = r.WithContext(withRequestLog(r.Context(), requestLogContext{id: requestID, start: start}))
	g.logEvent(LogLevelInfo, requestID, "request_start",
		"method", r.Method,
		"path", r.URL.EscapedPath(),
		"query_present", r.URL.RawQuery != "",
		"content_type", r.Header.Get("Content-Type"),
		"content_length", r.ContentLength,
		"remote_host", remoteHost(r.RemoteAddr),
	)

	mapping, err := g.redactRequestBody(r)
	if err != nil {
		g.logEvent(LogLevelError, requestID, "request_rejected", "error", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	if len(mapping) > 0 {
		ctx = withMapping(ctx, mapping)
	}
	lrw := &loggingResponseWriter{ResponseWriter: w}
	g.proxy.ServeHTTP(lrw, r.WithContext(ctx))
	g.logEvent(LogLevelInfo, requestID, "request_complete",
		"status", lrw.statusCode(),
		"bytes", lrw.bytes,
		"duration_ms", elapsedMillis(start),
	)
}

func (g *Gateway) redactRequestBody(r *http.Request) (map[string]string, error) {
	requestID := requestIDFromRequest(r)
	if r.Body == nil || r.Body == http.NoBody {
		g.logEvent(LogLevelDebug, requestID, "request_body_skip", "reason", "empty")
		return nil, nil
	}
	if !shouldTransform(r.Header) {
		g.logEvent(LogLevelDebug, requestID, "request_body_skip", "reason", "unsupported_content_type", "content_type", r.Header.Get("Content-Type"))
		return nil, nil
	}
	if isEncoded(r.Header) {
		g.logEvent(LogLevelInfo, requestID, "request_body_skip", "reason", "encoded", "content_encoding", r.Header.Get("Content-Encoding"))
		return nil, nil
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	_ = r.Body.Close()
	if len(body) == 0 {
		r.Body = http.NoBody
		r.ContentLength = 0
		g.logEvent(LogLevelDebug, requestID, "request_body_skip", "reason", "empty")
		return nil, nil
	}
	if status := g.requestBypassStatus(r, body); status.active {
		replaceRequestBody(r, body)
		g.logEvent(LogLevelInfo, requestID, "request_bypass",
			"reason", status.reason,
			"session_hash", status.sessionHash,
			"body_bytes", len(body),
		)
		return nil, nil
	} else if status.markerWithoutSession {
		g.logEvent(LogLevelDebug, requestID, "request_bypass_skip", "reason", "missing_session_id")
	}

	res, protectedRanges, err := g.redactBody(body, r.Header)
	if err != nil {
		return nil, err
	}
	redacted := []byte(res.Redacted)
	mapping := res.Mapping
	replaceRequestBody(r, redacted)
	g.logEvent(LogLevelInfo, requestID, "request_redact",
		"hit", res.Hit,
		"count", res.Count,
		"mapping_count", len(mapping),
		"protected_ranges", protectedRanges,
		"body_bytes_in", len(body),
		"body_bytes_out", len(redacted),
		"entities", summarizeEntities(res.Entities, 20),
	)
	g.logRequestReplacementDetails(requestID, res.Entities)
	g.logBodyEvent(requestID, "request_body_redacted", "body", string(redacted), "body_bytes", len(redacted))
	return mapping, nil
}

func (g *Gateway) redactBody(body []byte, h http.Header) (filter.ReversibleResult, int, error) {
	res := g.f.RedactReversible(string(body))
	protected := protectedJSONValueRangesForFields(body, protectedRequestJSONFields)
	if len(protected) == 0 {
		return res, 0, nil
	}
	return filterReversibleResult(body, res, protected), len(protected), nil
}

func (g *Gateway) restoreResponse(resp *http.Response) error {
	requestID := requestIDFromRequest(resp.Request)
	start := requestStartFromRequest(resp.Request)
	g.logEvent(LogLevelInfo, requestID, "response_received",
		"status", resp.StatusCode,
		"content_type", resp.Header.Get("Content-Type"),
		"content_length", resp.ContentLength,
		"duration_ms", elapsedMillis(start),
	)
	mapping := mappingFrom(resp.Request)
	if len(mapping) == 0 {
		g.logEvent(LogLevelDebug, requestID, "response_restore_skip", "reason", "no_mapping")
		return nil
	}
	if resp.Body == nil {
		g.logEvent(LogLevelDebug, requestID, "response_restore_skip", "reason", "empty")
		return nil
	}
	if !shouldTransform(resp.Header) {
		g.logEvent(LogLevelDebug, requestID, "response_restore_skip", "reason", "unsupported_content_type", "content_type", resp.Header.Get("Content-Type"))
		return nil
	}
	if isEncoded(resp.Header) {
		g.logEvent(LogLevelInfo, requestID, "response_restore_skip", "reason", "encoded", "content_encoding", resp.Header.Get("Content-Encoding"))
		return nil
	}
	if isSSE(resp.Header) {
		g.logEvent(LogLevelInfo, requestID, "response_restore_sse_start", "mapping_count", len(mapping))
		g.replaceSSEBody(resp, mapping, requestID)
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()

	restoreCounts := restoreCountsForBody(body, resp.Header, mapping)
	restored, mode, err := restoreBodyWithMode(body, resp.Header, mapping)
	if err != nil {
		g.logEvent(LogLevelError, requestID, "response_restore_error", "error", err.Error())
		return err
	}
	replaceResponseBody(resp, restored)
	g.logEvent(LogLevelInfo, requestID, "response_restore_body",
		"mode", mode,
		"mapping_count", len(mapping),
		"placeholder_hits", sumCounts(restoreCounts),
		"body_bytes_in", len(body),
		"body_bytes_out", len(restored),
	)
	g.logResponseRestoreDetails(requestID, mode, restoreCounts, mapping)
	g.logBodyEvent(requestID, "response_body_restored", "body", string(restored), "body_bytes", len(restored))
	return nil
}

func replaceRequestBody(r *http.Request, body []byte) {
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	r.Header.Set("Content-Length", strconv.Itoa(len(body)))
}

func replaceResponseBody(resp *http.Response, body []byte) {
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.Header.Del("Content-Encoding")
}

type byteRange struct {
	start int
	end   int
}

func protectedJSONValueRanges(body []byte, field string) []byteRange {
	return protectedJSONValueRangesForFields(body, []string{field})
}

func protectedJSONValueRangesForFields(body []byte, fields []string) []byteRange {
	var ranges []byteRange
	if len(body) == 0 || len(fields) == 0 || !json.Valid(body) {
		return ranges
	}
	for _, field := range fields {
		if field == "" {
			continue
		}
		ranges = append(ranges, protectedJSONValueRangesForField(body, field)...)
	}
	if len(ranges) <= 1 {
		return ranges
	}
	return mergeByteRanges(ranges)
}

func protectedJSONValueRangesForField(body []byte, field string) []byteRange {
	var ranges []byteRange
	pattern := []byte(strconv.Quote(field))
	for searchFrom := 0; searchFrom < len(body); {
		idx := bytes.Index(body[searchFrom:], pattern)
		if idx < 0 {
			break
		}
		keyStart := searchFrom + idx
		keyEnd := keyStart + len(pattern)
		i := skipJSONSpace(body, keyEnd)
		if i >= len(body) || body[i] != ':' {
			searchFrom = keyEnd
			continue
		}
		i = skipJSONSpace(body, i+1)
		if i >= len(body) || body[i] != '"' {
			searchFrom = keyEnd
			continue
		}
		end, ok := scanJSONStringEnd(body, i)
		if ok && shouldProtectRequestJSONValue(field, body[i:end]) {
			ranges = append(ranges, byteRange{start: i, end: end})
			searchFrom = end
			continue
		}
		searchFrom = keyEnd
	}
	return ranges
}

func shouldProtectRequestJSONValue(field string, quotedValue []byte) bool {
	if field == "encrypted_content" {
		return true
	}
	value, err := strconv.Unquote(string(quotedValue))
	if err != nil {
		return false
	}
	switch field {
	case "id":
		return isGatewayProtocolID(value)
	case "session_id", "codex_session_id":
		return isCodexSessionID(value)
	case "previous_response_id", "response_id":
		return strings.HasPrefix(value, "resp_")
	case "call_id", "tool_call_id":
		return strings.HasPrefix(value, "call_")
	case "item_id", "output_item_id":
		return isGatewayProtocolID(value)
	case "conversation_id":
		return strings.HasPrefix(value, "conv_")
	case "thread_id":
		return strings.HasPrefix(value, "thread_")
	case "run_id":
		return strings.HasPrefix(value, "run_")
	case "step_id":
		return strings.HasPrefix(value, "step_")
	case "assistant_id":
		return strings.HasPrefix(value, "asst_")
	case "file_id":
		return strings.HasPrefix(value, "file-")
	case "batch_id":
		return strings.HasPrefix(value, "batch_")
	default:
		return false
	}
}

func isCodexSessionID(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	for _, prefix := range []string{"codex-", "codex_", "session_", "sess_", "thread_", "conv_"} {
		if strings.HasPrefix(value, prefix) && len(value) > len(prefix) {
			return true
		}
	}
	return isUUID(value)
}

func isUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i := 0; i < len(value); i++ {
		switch i {
		case 8, 13, 18, 23:
			if value[i] != '-' {
				return false
			}
		default:
			if !isHexByte(value[i]) {
				return false
			}
		}
	}
	return true
}

func isHexByte(b byte) bool {
	return (b >= '0' && b <= '9') ||
		(b >= 'a' && b <= 'f') ||
		(b >= 'A' && b <= 'F')
}

func isGatewayProtocolID(value string) bool {
	for _, prefix := range []string{
		"call_", "resp_", "msg_", "item_", "fc_", "rs_", "run_", "step_",
		"thread_", "asst_", "batch_", "conv_", "toolu_",
		"file-", "chatcmpl-", "cmpl-",
	} {
		if strings.HasPrefix(value, prefix) && len(value) > len(prefix) {
			return true
		}
	}
	return false
}

type bypassSessions struct {
	marker string
	max    int
	mu     sync.Mutex
	seen   map[string]time.Time
}

type bypassStatus struct {
	active               bool
	markerWithoutSession bool
	reason               string
	sessionHash          string
}

func newBypassSessions(marker string, max int) bypassSessions {
	marker = strings.TrimSpace(marker)
	if max <= 0 {
		max = defaultMaxBypassSessions
	}
	if marker == "" {
		return bypassSessions{}
	}
	return bypassSessions{
		marker: marker,
		max:    max,
		seen:   make(map[string]time.Time),
	}
}

func (g *Gateway) requestBypassStatus(r *http.Request, body []byte) bypassStatus {
	if g == nil || g.bypass.marker == "" {
		return bypassStatus{}
	}
	sessionID := codexSessionIDFromRequest(r, body)
	hasMarker := bytes.Contains(body, []byte(g.bypass.marker))
	if sessionID == "" {
		return bypassStatus{markerWithoutSession: hasMarker}
	}
	if hasMarker {
		g.bypass.mark(sessionID)
		return bypassStatus{active: true, reason: "marker", sessionHash: sessionHash(sessionID)}
	}
	if g.bypass.has(sessionID) {
		return bypassStatus{active: true, reason: "session", sessionHash: sessionHash(sessionID)}
	}
	return bypassStatus{}
}

func (b *bypassSessions) mark(sessionID string) {
	if b == nil || b.marker == "" || sessionID == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.seen == nil {
		b.seen = make(map[string]time.Time)
	}
	b.seen[sessionID] = time.Now()
	if len(b.seen) > b.max {
		b.pruneLocked()
	}
}

func (b *bypassSessions) has(sessionID string) bool {
	if b == nil || b.marker == "" || sessionID == "" {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.seen == nil {
		return false
	}
	if _, ok := b.seen[sessionID]; !ok {
		return false
	}
	b.seen[sessionID] = time.Now()
	return true
}

func (b *bypassSessions) pruneLocked() {
	type sessionAge struct {
		id       string
		lastSeen time.Time
	}
	entries := make([]sessionAge, 0, len(b.seen))
	for id, lastSeen := range b.seen {
		entries = append(entries, sessionAge{id: id, lastSeen: lastSeen})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].lastSeen.Before(entries[j].lastSeen)
	})
	target := b.max
	if target <= 0 {
		target = defaultMaxBypassSessions
	}
	for len(b.seen) > target && len(entries) > 0 {
		delete(b.seen, entries[0].id)
		entries = entries[1:]
	}
}

func codexSessionIDFromRequest(r *http.Request, body []byte) string {
	for _, header := range codexSessionIDHeaders {
		if value := validCodexSessionID(r.Header.Get(header)); value != "" {
			return value
		}
	}
	if len(body) == 0 {
		return ""
	}
	if isJSON(r.Header) {
		return codexSessionIDFromJSON(body)
	}
	if mediaType(r.Header) == "application/x-www-form-urlencoded" {
		values, err := url.ParseQuery(string(body))
		if err != nil {
			return ""
		}
		for _, field := range codexSessionIDFields {
			if value := validCodexSessionID(values.Get(field)); value != "" {
				return value
			}
		}
	}
	return ""
}

func codexSessionIDFromJSON(body []byte) string {
	var payload any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&payload); err != nil {
		return ""
	}
	return codexSessionIDFromValue(payload, 0)
}

func codexSessionIDFromValue(value any, depth int) string {
	if depth > 12 {
		return ""
	}
	switch x := value.(type) {
	case map[string]any:
		if sessionID := codexSessionIDFromObject(x); sessionID != "" {
			return sessionID
		}
		for _, child := range x {
			if sessionID := codexSessionIDFromValue(child, depth+1); sessionID != "" {
				return sessionID
			}
		}
	case []any:
		for _, child := range x {
			if sessionID := codexSessionIDFromValue(child, depth+1); sessionID != "" {
				return sessionID
			}
		}
	}
	return ""
}

func codexSessionIDFromObject(obj map[string]any) string {
	for _, field := range codexSessionIDFields {
		value, ok := obj[field].(string)
		if !ok {
			continue
		}
		if value = validCodexSessionID(value); value != "" {
			return value
		}
	}
	return ""
}

func validCodexSessionID(value string) string {
	value = strings.TrimSpace(value)
	if isCodexSessionID(value) {
		return value
	}
	return ""
}

func sessionHash(sessionID string) string {
	sum := sha256.Sum256([]byte(sessionID))
	return hex.EncodeToString(sum[:])[:16]
}

func mergeByteRanges(ranges []byteRange) []byteRange {
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].start != ranges[j].start {
			return ranges[i].start < ranges[j].start
		}
		return ranges[i].end < ranges[j].end
	})
	merged := ranges[:0]
	for _, r := range ranges {
		if len(merged) == 0 || r.start > merged[len(merged)-1].end {
			merged = append(merged, r)
			continue
		}
		if r.end > merged[len(merged)-1].end {
			merged[len(merged)-1].end = r.end
		}
	}
	return merged
}

func skipJSONSpace(body []byte, i int) int {
	for i < len(body) {
		switch body[i] {
		case ' ', '\n', '\r', '\t':
			i++
		default:
			return i
		}
	}
	return i
}

func scanJSONStringEnd(body []byte, start int) (int, bool) {
	if start >= len(body) || body[start] != '"' {
		return 0, false
	}
	escaped := false
	for i := start + 1; i < len(body); i++ {
		if escaped {
			escaped = false
			continue
		}
		switch body[i] {
		case '\\':
			escaped = true
		case '"':
			return i + 1, true
		}
	}
	return 0, false
}

func filterReversibleResult(body []byte, res filter.ReversibleResult, protected []byteRange) filter.ReversibleResult {
	if len(res.Entities) == 0 {
		return res
	}
	entities := make([]filter.Entity, 0, len(res.Entities))
	for _, entity := range res.Entities {
		if overlapsProtectedRange(entity.Start, entity.End, protected) {
			continue
		}
		entities = append(entities, entity)
	}
	if len(entities) == len(res.Entities) {
		return res
	}
	mapping := make(map[string]string, len(entities))
	for _, entity := range entities {
		if entity.Placeholder != "" {
			mapping[entity.Placeholder] = entity.Text
		}
	}
	var b strings.Builder
	prev := 0
	for _, entity := range entities {
		b.Write(body[prev:entity.Start])
		b.WriteString(entity.Placeholder)
		prev = entity.End
	}
	b.Write(body[prev:])
	res.Redacted = b.String()
	res.Hit = len(entities) > 0
	res.Count = len(entities)
	res.Entities = entities
	res.Mapping = mapping
	return res
}

func overlapsProtectedRange(start, end int, protected []byteRange) bool {
	for _, r := range protected {
		if start < r.end && end > r.start {
			return true
		}
	}
	return false
}

func (g *Gateway) replaceSSEBody(resp *http.Response, mapping map[string]string, requestID string) {
	pr, pw := io.Pipe()
	original := resp.Body
	stats := &sseStats{}
	start := time.Now()
	go func() {
		err := restoreSSEStreamWithStats(pw, original, mapping, stats)
		if err != nil {
			g.logResponseRestoreDetails(requestID, "sse", stats.restoreCounts, mapping)
			g.logEvent(LogLevelError, requestID, "response_restore_sse_error",
				"error", err.Error(),
				"events", stats.events,
				"data_lines", stats.dataLines,
				"delta_events", stats.deltaEvents,
				"placeholder_hits", stats.placeholderHits,
				"bytes_out", stats.bytesOut,
				"duration_ms", elapsedMillis(start),
			)
			_ = pw.CloseWithError(err)
			return
		}
		g.logResponseRestoreDetails(requestID, "sse", stats.restoreCounts, mapping)
		g.logEvent(LogLevelInfo, requestID, "response_restore_sse_complete",
			"events", stats.events,
			"data_lines", stats.dataLines,
			"delta_events", stats.deltaEvents,
			"text_fallbacks", stats.textFallbacks,
			"flushes", stats.flushes,
			"placeholder_hits", stats.placeholderHits,
			"bytes_out", stats.bytesOut,
			"duration_ms", elapsedMillis(start),
		)
		_ = pw.Close()
	}()
	resp.Body = pr
	resp.ContentLength = -1
	resp.Header.Del("Content-Length")
	resp.Header.Del("Content-Encoding")
}

func restoreBody(body []byte, h http.Header, mapping map[string]string) ([]byte, error) {
	restored, _, err := restoreBodyWithMode(body, h, mapping)
	return restored, err
}

func restoreBodyWithMode(body []byte, h http.Header, mapping map[string]string) ([]byte, string, error) {
	if isJSON(h) {
		if payload, err := parseJSONBody(body); err == nil {
			restored, err := filter.RestoreJSON(payload, mapping)
			if err != nil {
				return nil, "", err
			}
			out, err := marshalJSON(restored)
			return out, "json", err
		}
		return []byte(filter.RestoreText(string(body), mapping)), "text_json_parse_fallback", nil
	}
	return []byte(filter.RestoreText(string(body), mapping)), "text", nil
}

func parseJSONBody(body []byte) (any, error) {
	var payload any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func shouldTransform(h http.Header) bool {
	ct := h.Get("Content-Type")
	if ct == "" {
		return true
	}
	mediaType := mediaType(h)
	return strings.HasPrefix(mediaType, "text/") ||
		mediaType == "application/json" ||
		strings.HasSuffix(mediaType, "+json") ||
		mediaType == "application/x-www-form-urlencoded" ||
		mediaType == "application/graphql"
}

func isEncoded(h http.Header) bool {
	return h.Get("Content-Encoding") != ""
}

func isSSE(h http.Header) bool {
	return mediaType(h) == "text/event-stream"
}

func isJSON(h http.Header) bool {
	mt := mediaType(h)
	return mt == "application/json" || strings.HasSuffix(mt, "+json")
}

func mediaType(h http.Header) string {
	ct := h.Get("Content-Type")
	if ct == "" {
		return ""
	}
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		mediaType = strings.TrimSpace(strings.Split(ct, ";")[0])
	}
	return strings.ToLower(mediaType)
}

type requestLogContext struct {
	id    string
	start time.Time
}

func normalizeLogLevel(level LogLevel) LogLevel {
	if level == LogLevelDefault {
		return LogLevelInfo
	}
	return level
}

func (g *Gateway) shouldLog(level LogLevel) bool {
	return level <= g.logLevel
}

func (g *Gateway) logEvent(level LogLevel, requestID, event string, kv ...any) {
	if g == nil || g.logger == nil || !g.shouldLog(level) {
		return
	}
	g.logger.Printf("%s", buildLogLine(level, requestID, event, kv...))
}

func (g *Gateway) logBodyEvent(requestID, event, field, body string, kv ...any) {
	if g == nil || g.logger == nil || !g.debugBody || !g.shouldLog(LogLevelDebug) {
		return
	}
	truncatedBody, truncated := truncateLogString(body, g.maxBodyLogBytes)
	fields := make([]any, 0, len(kv)+4)
	fields = append(fields, kv...)
	fields = append(fields, field, truncatedBody, "truncated", truncated)
	g.logger.Printf("%s", buildLogLine(LogLevelDebug, requestID, event, fields...))
}

func (g *Gateway) logRequestReplacementDetails(requestID string, entities []filter.Entity) {
	for _, entity := range entities {
		if entity.Placeholder == "" {
			continue
		}
		g.logEvent(LogLevelInfo, requestID, "request_replace",
			"type", entity.Type,
			"placeholder", entity.Placeholder,
			"original", entity.Text,
			"start", entity.Start,
			"end", entity.End,
			"bytes", entity.End-entity.Start,
		)
	}
}

func (g *Gateway) logResponseRestoreDetails(requestID, mode string, counts map[string]int, mapping map[string]string) {
	if len(counts) == 0 || len(mapping) == 0 {
		return
	}
	placeholders := make([]string, 0, len(counts))
	for placeholder, count := range counts {
		if count > 0 {
			placeholders = append(placeholders, placeholder)
		}
	}
	sort.Strings(placeholders)
	for _, placeholder := range placeholders {
		g.logEvent(LogLevelInfo, requestID, "response_restore",
			"mode", mode,
			"placeholder", placeholder,
			"original", mapping[placeholder],
			"count", counts[placeholder],
		)
	}
}

func buildLogLine(level LogLevel, requestID, event string, kv ...any) string {
	var b strings.Builder
	b.WriteString("level=")
	b.WriteString(level.String())
	b.WriteString(" event=")
	b.WriteString(formatLogValue(event))
	if requestID != "" {
		b.WriteString(" request_id=")
		b.WriteString(formatLogValue(requestID))
	}
	for i := 0; i+1 < len(kv); i += 2 {
		key, ok := kv[i].(string)
		if !ok || key == "" {
			continue
		}
		b.WriteByte(' ')
		b.WriteString(key)
		b.WriteByte('=')
		b.WriteString(formatLogValue(kv[i+1]))
	}
	return b.String()
}

func formatLogValue(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case string:
		return strconv.Quote(x)
	case fmt.Stringer:
		return strconv.Quote(x.String())
	case bool:
		if x {
			return "true"
		}
		return "false"
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case int32:
		return strconv.FormatInt(int64(x), 10)
	case uint:
		return strconv.FormatUint(uint64(x), 10)
	case uint64:
		return strconv.FormatUint(x, 10)
	case uint32:
		return strconv.FormatUint(uint64(x), 10)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(x), 'f', -1, 32)
	default:
		return strconv.Quote(fmt.Sprint(x))
	}
}

func truncateLogString(s string, maxBytes int) (string, bool) {
	if maxBytes <= 0 {
		maxBytes = defaultMaxBodyLogBytes
	}
	if len(s) <= maxBytes {
		return s, false
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	if cut <= 0 {
		cut = maxBytes
	}
	return s[:cut] + "...<truncated>", true
}

type entityLogSummary struct {
	Type        string `json:"type"`
	Placeholder string `json:"placeholder,omitempty"`
	Start       int    `json:"start"`
	End         int    `json:"end"`
	Bytes       int    `json:"bytes"`
}

func summarizeEntities(entities []filter.Entity, max int) string {
	if len(entities) == 0 {
		return "[]"
	}
	if max <= 0 || max > len(entities) {
		max = len(entities)
	}
	out := make([]entityLogSummary, 0, max)
	for _, e := range entities[:max] {
		out = append(out, entityLogSummary{
			Type:        e.Type,
			Placeholder: e.Placeholder,
			Start:       e.Start,
			End:         e.End,
			Bytes:       e.End - e.Start,
		})
	}
	b, err := json.Marshal(out)
	if err != nil {
		return "[]"
	}
	if len(entities) > max {
		return strings.TrimSuffix(string(b), "]") + fmt.Sprintf(`,{"truncated":%d}]`, len(entities)-max)
	}
	return string(b)
}

func requestIDFor(r *http.Request) string {
	if r == nil {
		return newRequestID()
	}
	if id := strings.TrimSpace(r.Header.Get(requestIDHeader)); id != "" {
		return id
	}
	return newRequestID()
}

func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err == nil {
		return hex.EncodeToString(b[:])
	}
	return strconv.FormatInt(time.Now().UnixNano(), 16)
}

func withRequestLog(ctx context.Context, info requestLogContext) context.Context {
	return context.WithValue(ctx, requestLogContextKey{}, info)
}

func requestLogFromContext(ctx context.Context) requestLogContext {
	if ctx == nil {
		return requestLogContext{}
	}
	info, _ := ctx.Value(requestLogContextKey{}).(requestLogContext)
	return info
}

func requestIDFromContext(ctx context.Context) string {
	return requestLogFromContext(ctx).id
}

func requestIDFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	if id := requestIDFromContext(r.Context()); id != "" {
		return id
	}
	return strings.TrimSpace(r.Header.Get(requestIDHeader))
}

func requestStartFromRequest(r *http.Request) time.Time {
	if r == nil {
		return time.Time{}
	}
	return requestLogFromContext(r.Context()).start
}

func elapsedMillis(start time.Time) int64 {
	if start.IsZero() {
		return 0
	}
	return time.Since(start).Milliseconds()
}

func remoteHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

type loggingResponseWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *loggingResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *loggingResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	return n, err
}

func (w *loggingResponseWriter) statusCode() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

func (w *loggingResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *loggingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return h.Hijack()
}

func (w *loggingResponseWriter) ReadFrom(r io.Reader) (int64, error) {
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		if w.status == 0 {
			w.status = http.StatusOK
		}
		n, err := rf.ReadFrom(r)
		w.bytes += n
		return n, err
	}
	return io.Copy(struct{ io.Writer }{w}, r)
}

func withMapping(ctx context.Context, mapping map[string]string) context.Context {
	return context.WithValue(ctx, mappingContextKey{}, mapping)
}

func mappingFrom(r *http.Request) map[string]string {
	if r == nil {
		return nil
	}
	mapping, _ := r.Context().Value(mappingContextKey{}).(map[string]string)
	return mapping
}

func restoreSSEStream(dst *io.PipeWriter, src io.ReadCloser, mapping map[string]string) error {
	return restoreSSEStreamWithStats(dst, src, mapping, nil)
}

func restoreSSEStreamWithStats(dst *io.PipeWriter, src io.ReadCloser, mapping map[string]string, stats *sseStats) error {
	defer src.Close()
	restorer := newSSERestorerWithStats(mapping, stats)
	reader := bufio.NewReader(src)
	var lines []string
	for {
		line, err := reader.ReadString('\n')
		if line != "" {
			lines = append(lines, line)
			if isBlankSSELine(line) {
				out := restorer.processEvent(lines)
				if stats != nil {
					stats.bytesOut += len(out)
				}
				if _, writeErr := dst.Write(out); writeErr != nil {
					return writeErr
				}
				lines = nil
			}
		}
		if err != nil {
			if err == io.EOF {
				if len(lines) > 0 {
					out := restorer.processEvent(lines)
					if stats != nil {
						stats.bytesOut += len(out)
					}
					if _, writeErr := dst.Write(out); writeErr != nil {
						return writeErr
					}
				}
				out := restorer.flushAll()
				if stats != nil {
					stats.bytesOut += len(out)
				}
				if _, writeErr := dst.Write(out); writeErr != nil {
					return writeErr
				}
				return nil
			}
			return err
		}
	}
}

type sseStats struct {
	events          int
	dataLines       int
	deltaEvents     int
	textFallbacks   int
	flushes         int
	placeholderHits int
	bytesOut        int
	restoreCounts   map[string]int
}

func (s *sseStats) addRestoreCounts(counts map[string]int) {
	if s == nil || len(counts) == 0 {
		return
	}
	if s.restoreCounts == nil {
		s.restoreCounts = make(map[string]int, len(counts))
	}
	for placeholder, count := range counts {
		if count <= 0 {
			continue
		}
		s.placeholderHits += count
		s.restoreCounts[placeholder] += count
	}
}

type sseRestorer struct {
	mapping         map[string]string
	keepBytes       int
	pending         map[string]string
	lastDeltaEvent  map[string]string
	lastDeltaObject map[string]map[string]any
	stats           *sseStats
}

func newSSERestorer(mapping map[string]string) *sseRestorer {
	return newSSERestorerWithStats(mapping, nil)
}

func newSSERestorerWithStats(mapping map[string]string, stats *sseStats) *sseRestorer {
	maxLen := 0
	for placeholder := range mapping {
		if len(placeholder) > maxLen {
			maxLen = len(placeholder)
		}
	}
	if maxLen == 0 {
		maxLen = 1
	}
	return &sseRestorer{
		mapping:         mapping,
		keepBytes:       maxLen - 1,
		pending:         make(map[string]string),
		lastDeltaEvent:  make(map[string]string),
		lastDeltaObject: make(map[string]map[string]any),
		stats:           stats,
	}
}

func (r *sseRestorer) processEvent(lines []string) []byte {
	if r.stats != nil {
		r.stats.events++
	}
	eventName, payloads := inspectSSEEvent(lines)
	var out bytes.Buffer
	if !payloads.hasDelta && r.hasPending() {
		out.Write(r.flushAll())
	}
	for _, line := range lines {
		content := trimSSELine(line)
		name, value, ok := parseSSEField(content)
		if !ok || name != "data" {
			out.WriteString(content)
			out.WriteByte('\n')
			continue
		}
		transformed, handled := r.transformData(value, eventName)
		if handled {
			if r.stats != nil {
				r.stats.dataLines++
			}
			out.WriteString("data: ")
			out.Write(transformed)
			out.WriteByte('\n')
			continue
		}
		out.WriteString(content)
		out.WriteByte('\n')
	}
	return out.Bytes()
}

func (r *sseRestorer) transformData(value, eventName string) ([]byte, bool) {
	if strings.TrimSpace(value) == "[DONE]" {
		return []byte("[DONE]"), true
	}
	var payload map[string]any
	dec := json.NewDecoder(strings.NewReader(value))
	dec.UseNumber()
	if err := dec.Decode(&payload); err != nil {
		if r.stats != nil {
			r.stats.textFallbacks++
			r.stats.addRestoreCounts(countPlaceholderHitsByKey(value, r.mapping))
		}
		return []byte(filter.RestoreText(value, r.mapping)), true
	}
	typ, _ := payload["type"].(string)
	if typ == "" {
		typ = eventName
	}
	if delta, ok := payload["delta"].(string); ok && isDeltaEvent(typ) {
		key := deltaKey(typ, payload)
		payload["delta"] = r.transformDelta(key, delta)
		if r.stats != nil {
			r.stats.deltaEvents++
		}
		r.lastDeltaEvent[key] = eventName
		if r.lastDeltaEvent[key] == "" {
			r.lastDeltaEvent[key] = typ
		}
		r.lastDeltaObject[key] = cloneObject(payload)
		out, err := marshalJSON(payload)
		if err != nil {
			return []byte(value), true
		}
		return out, true
	}
	counts := countPlaceholdersInValue(payload, r.mapping)
	restored, err := filter.RestoreJSON(payload, r.mapping)
	if err != nil {
		return []byte(value), true
	}
	if r.stats != nil {
		r.stats.addRestoreCounts(counts)
	}
	out, err := marshalJSON(restored)
	if err != nil {
		return []byte(value), true
	}
	return out, true
}

func (r *sseRestorer) transformDelta(key, delta string) string {
	combined := r.pending[key] + delta
	if r.stats != nil {
		r.stats.addRestoreCounts(countPlaceholderHitsByKey(combined, r.mapping))
	}
	restored := filter.RestoreText(combined, r.mapping)
	prefix, suffix := splitStreamingSuffix(restored, r.keepBytes)
	r.pending[key] = suffix
	return prefix
}

func (r *sseRestorer) flushAll() []byte {
	if !r.hasPending() {
		return nil
	}
	var out bytes.Buffer
	for key, pending := range r.pending {
		if pending == "" {
			continue
		}
		payload := cloneObject(r.lastDeltaObject[key])
		if payload == nil {
			payload = map[string]any{"type": r.lastDeltaEvent[key]}
		}
		payload["delta"] = filter.RestoreText(pending, r.mapping)
		eventName := r.lastDeltaEvent[key]
		if eventName != "" {
			out.WriteString("event: ")
			out.WriteString(eventName)
			out.WriteByte('\n')
		}
		data, err := marshalJSON(payload)
		if err != nil {
			continue
		}
		out.WriteString("data: ")
		out.Write(data)
		out.WriteString("\n\n")
		r.pending[key] = ""
	}
	if r.stats != nil && out.Len() > 0 {
		r.stats.flushes++
	}
	return out.Bytes()
}

func (r *sseRestorer) hasPending() bool {
	for _, pending := range r.pending {
		if pending != "" {
			return true
		}
	}
	return false
}

type ssePayloadInfo struct {
	hasDelta bool
}

func inspectSSEEvent(lines []string) (string, ssePayloadInfo) {
	var eventName string
	var info ssePayloadInfo
	for _, line := range lines {
		content := trimSSELine(line)
		name, value, ok := parseSSEField(content)
		if !ok {
			continue
		}
		switch name {
		case "event":
			eventName = value
		case "data":
			var payload map[string]any
			if err := json.Unmarshal([]byte(value), &payload); err != nil {
				continue
			}
			typ, _ := payload["type"].(string)
			if typ == "" {
				typ = eventName
			}
			if _, ok := payload["delta"].(string); ok && isDeltaEvent(typ) {
				info.hasDelta = true
			}
		}
	}
	return eventName, info
}

func isDeltaEvent(typ string) bool {
	return strings.HasSuffix(typ, ".delta") || strings.Contains(typ, "_delta")
}

func deltaKey(typ string, payload map[string]any) string {
	parts := []string{typ}
	for _, field := range []string{"item_id", "output_index", "content_index", "summary_index", "call_id"} {
		if v, ok := payload[field]; ok {
			parts = append(parts, field+"="+toKeyString(v))
		}
	}
	return strings.Join(parts, "|")
}

func toKeyString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	default:
		return ""
	}
}

func countPlaceholderHits(s string, mapping map[string]string) int {
	return sumCounts(countPlaceholderHitsByKey(s, mapping))
}

func countPlaceholderHitsByKey(s string, mapping map[string]string) map[string]int {
	if s == "" || len(mapping) == 0 {
		return nil
	}
	counts := make(map[string]int)
	for placeholder := range mapping {
		if count := strings.Count(s, placeholder); count > 0 {
			counts[placeholder] = count
		}
	}
	if len(counts) == 0 {
		return nil
	}
	return counts
}

func restoreCountsForBody(body []byte, h http.Header, mapping map[string]string) map[string]int {
	if len(body) == 0 || len(mapping) == 0 {
		return nil
	}
	if isJSON(h) {
		if payload, err := parseJSONBody(body); err == nil {
			return countPlaceholdersInValue(payload, mapping)
		}
	}
	return countPlaceholderHitsByKey(string(body), mapping)
}

func countPlaceholdersInValue(v any, mapping map[string]string) map[string]int {
	counts := make(map[string]int)
	addPlaceholderCountsFromValue(counts, v, mapping)
	if len(counts) == 0 {
		return nil
	}
	return counts
}

func addPlaceholderCountsFromValue(counts map[string]int, v any, mapping map[string]string) {
	switch x := v.(type) {
	case string:
		mergeCounts(counts, countPlaceholderHitsByKey(x, mapping))
	case []any:
		for _, item := range x {
			addPlaceholderCountsFromValue(counts, item, mapping)
		}
	case map[string]any:
		for _, item := range x {
			addPlaceholderCountsFromValue(counts, item, mapping)
		}
	}
}

func mergeCounts(dst, src map[string]int) {
	for key, count := range src {
		if count > 0 {
			dst[key] += count
		}
	}
}

func sumCounts(counts map[string]int) int {
	total := 0
	for _, count := range counts {
		total += count
	}
	return total
}

func splitStreamingSuffix(s string, keepBytes int) (string, string) {
	if keepBytes <= 0 || len(s) <= keepBytes {
		if keepBytes <= 0 {
			return s, ""
		}
		return "", s
	}
	cut := len(s) - keepBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	if cut <= 0 {
		return "", s
	}
	return s[:cut], s[cut:]
}

func parseSSEField(line string) (string, string, bool) {
	if line == "" || strings.HasPrefix(line, ":") {
		return "", "", false
	}
	idx := strings.IndexByte(line, ':')
	if idx < 0 {
		return line, "", true
	}
	value := line[idx+1:]
	if strings.HasPrefix(value, " ") {
		value = value[1:]
	}
	return line[:idx], value, true
}

func isBlankSSELine(line string) bool {
	return trimSSELine(line) == ""
}

func trimSSELine(line string) string {
	return strings.TrimRight(line, "\r\n")
}

func cloneObject(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func marshalJSON(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}
