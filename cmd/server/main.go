// 单进程同时跑 HTTP 和 gRPC，共享同一个 *filter.Filter
// （gitleaks 规则只编译一份，省内存、好维护）。
package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"

	"privacyfilter/filter"
	"privacyfilter/internal/grpcapi"
	"privacyfilter/internal/httpapi"
)

func main() {
	tomlPath := envOr("PF_GITLEAKS_TOML", "rules/gitleaks.toml")
	httpAddr := ":" + envOr("PF_PORT", "8088")
	grpcAddr := ":" + envOr("PF_GRPC_PORT", "8089")

	f, err := filter.New(tomlPath)
	if err != nil {
		log.Printf("加载 %s 失败：%v —— 改用内置规则", tomlPath, err)
		f, _ = filter.New("")
	}
	rules, skipped := f.Stats()
	log.Printf("就绪：gitleaks 规则 %d 条（跳过 %d 条不兼容）", rules, skipped)

	// --- gRPC ---
	lis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		log.Fatalf("gRPC 监听 %s 失败：%v", grpcAddr, err)
	}
	gs := grpc.NewServer()
	grpcapi.Register(gs, f)
	go func() {
		log.Printf("gRPC 监听 %s", grpcAddr)
		if err := gs.Serve(lis); err != nil {
			log.Printf("gRPC 退出：%v", err)
		}
	}()

	// --- HTTP ---
	hs := &http.Server{
		Addr:    httpAddr,
		Handler: httpapi.Handler(f),
	}
	go func() {
		log.Printf("HTTP 监听 %s", httpAddr)
		if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("HTTP 退出：%v", err)
		}
	}()

	// 等关闭信号，优雅退出
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	log.Println("收到关闭信号，正在退出……")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = hs.Shutdown(ctx)
	gs.GracefulStop()
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
