// Package config 放置服务入口共享的配置解析。
package config

import (
	"fmt"
	"os"
	"time"

	"privacyfilter/store"
)

// SessionTTL 从 PF_SESSION_TTL 读取可逆脱敏 session 生命周期。
func SessionTTL() (time.Duration, error) {
	raw := os.Getenv("PF_SESSION_TTL")
	if raw == "" {
		return store.DefaultTTL, nil
	}
	ttl, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid PF_SESSION_TTL %q: %w", raw, err)
	}
	if ttl <= 0 {
		return 0, fmt.Errorf("PF_SESSION_TTL must be positive")
	}
	return ttl, nil
}
