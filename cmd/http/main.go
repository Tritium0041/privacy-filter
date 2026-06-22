// 单独的 HTTP 服务。逻辑全部在 internal/httpapi。
package main

import (
	"log"
	"net/http"
	"os"

	"privacyfilter/filter"
	"privacyfilter/internal/config"
	"privacyfilter/internal/httpapi"
	"privacyfilter/store"
)

func main() {
	tomlPath := envOr("PF_GITLEAKS_TOML", "rules/gitleaks.toml")
	addr := ":" + envOr("PF_PORT", "8088")

	f, err := filter.New(tomlPath)
	if err != nil {
		log.Printf("加载 %s 失败：%v —— 改用内置规则", tomlPath, err)
		f, _ = filter.New("")
	}
	rules, skipped := f.Stats()
	log.Printf("就绪：gitleaks 规则 %d 条（跳过 %d 条不兼容）", rules, skipped)
	sessionTTL, err := config.SessionTTL()
	if err != nil {
		log.Fatal(err)
	}
	sessions := store.NewMemoryStore()
	log.Printf("可逆脱敏 session TTL：%s", sessionTTL)

	log.Printf("HTTP 监听 %s", addr)
	log.Fatal(http.ListenAndServe(addr, httpapi.HandlerWithStore(f, sessions, sessionTTL)))
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
