// 示例反向代理网关：请求转发前可逆脱敏，响应返回前自动还原占位符。
package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"privacyfilter/filter"
	"privacyfilter/internal/gateway"
)

func main() {
	upstreamRaw := os.Getenv("PF_GATEWAY_UPSTREAM")
	if upstreamRaw == "" {
		log.Fatal("PF_GATEWAY_UPSTREAM is required, for example https://api.openai.com")
	}
	upstream, err := url.Parse(upstreamRaw)
	if err != nil {
		log.Fatalf("invalid PF_GATEWAY_UPSTREAM: %v", err)
	}
	if upstream.Scheme == "" || upstream.Host == "" {
		log.Fatal("PF_GATEWAY_UPSTREAM must include scheme and host")
	}

	tomlPath := envOr("PF_GITLEAKS_TOML", "rules/gitleaks.toml")
	addr := ":" + envOr("PF_GATEWAY_PORT", "8090")
	logFilePath := envOr("PF_GATEWAY_LOG_FILE", "privacy-gateway.log")
	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		log.Fatalf("open gateway log file %s failed: %v", logFilePath, err)
	}
	defer logFile.Close()
	logger := log.New(io.MultiWriter(os.Stderr, logFile), "", log.LstdFlags)
	log.SetOutput(io.MultiWriter(os.Stderr, logFile))

	disableEntropyFallback, err := envBoolOr("PF_DISABLE_ENTROPY_FALLBACK", true)
	if err != nil {
		log.Fatal(err)
	}

	f, err := filter.NewWithOptions(tomlPath, filter.Options{DisableEntropyFallback: disableEntropyFallback})
	if err != nil {
		log.Printf("加载 %s 失败：%v —— 改用内置规则", tomlPath, err)
		f, _ = filter.NewWithOptions("", filter.Options{DisableEntropyFallback: disableEntropyFallback})
	}
	rules, skipped := f.Stats()
	log.Printf("就绪：gitleaks 规则 %d 条（跳过 %d 条不兼容）", rules, skipped)
	log.Printf("隐私网关监听 %s，上游 %s", addr, upstream.String())
	log.Printf("网关日志文件：%s", logFilePath)
	log.Printf("高熵兜底检测：%s", enabledLabel(!disableEntropyFallback))

	logLevel, err := gateway.ParseLogLevel(envOr("PF_GATEWAY_LOG_LEVEL", "info"))
	if err != nil {
		log.Fatal(err)
	}
	debugBody := os.Getenv("PF_GATEWAY_DEBUG_BODY") == "1"
	maxBodyLogBytes := envIntOr("PF_GATEWAY_LOG_BODY_BYTES", 4096)
	if maxBodyLogBytes <= 0 {
		log.Fatal("PF_GATEWAY_LOG_BODY_BYTES must be positive")
	}
	bypassMarker := os.Getenv("PF_GATEWAY_BYPASS_MARKER")
	log.Printf("网关日志级别：%s", logLevel.String())
	if bypassMarker != "" {
		log.Printf("Codex session bypass：已启用")
	}
	if debugBody {
		log.Printf("请求/响应 body 调试日志已开启：最多记录 %d bytes，只在本地排查时使用", maxBodyLogBytes)
	}

	log.Fatal(http.ListenAndServe(addr, gateway.NewWithOptions(f, upstream, gateway.Options{
		Logger:          logger,
		LogLevel:        logLevel,
		DebugBody:       debugBody,
		MaxBodyLogBytes: maxBodyLogBytes,
		BypassMarker:    bypassMarker,
	})))
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envIntOr(key string, def int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		log.Fatalf("%s must be an integer: %v", key, err)
	}
	return value
}

func envBoolOr(key string, def bool) (bool, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return def, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean: %w", key, err)
	}
	return value, nil
}

func enabledLabel(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled"
}
