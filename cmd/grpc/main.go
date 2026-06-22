// 单独的 gRPC 服务。逻辑全部在 internal/grpcapi。
package main

import (
	"log"
	"net"
	"os"

	"google.golang.org/grpc"

	"privacyfilter/filter"
	"privacyfilter/internal/config"
	"privacyfilter/internal/grpcapi"
	"privacyfilter/store"
)

func main() {
	tomlPath := envOr("PF_GITLEAKS_TOML", "rules/gitleaks.toml")
	addr := ":" + envOr("PF_GRPC_PORT", "8089")

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

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("监听 %s 失败：%v", addr, err)
	}
	s := grpc.NewServer()
	grpcapi.RegisterWithStore(s, f, sessions, sessionTTL)

	log.Printf("gRPC 监听 %s", addr)
	log.Fatal(s.Serve(lis))
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
