package grpcapi

import (
	"context"
	"net"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"privacyfilter/filter"
	pb "privacyfilter/gen/filterpb"
)

// TestGRPCRedact 用 bufconn 起一个进程内 gRPC 服务，端到端验证 Redact。
func TestGRPCRedact(t *testing.T) {
	pf, err := filter.New("../../rules/gitleaks.toml")
	if err != nil {
		t.Fatalf("filter.New: %v", err)
	}

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	Register(srv, pf)
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	client := pb.NewPrivacyFilterClient(conn)
	resp, err := client.Redact(context.Background(), &pb.RedactRequest{
		Text: "邮箱 a@b.com 密码是 Hunter2xy",
	})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if !strings.Contains(resp.GetRedacted(), "[邮箱]") || !strings.Contains(resp.GetRedacted(), "[密钥]") {
		t.Errorf("脱敏不全: %q", resp.GetRedacted())
	}
	if !resp.GetHit() || resp.GetCount() < 2 {
		t.Errorf("hit/count 不对: hit=%v count=%d", resp.GetHit(), resp.GetCount())
	}
}
