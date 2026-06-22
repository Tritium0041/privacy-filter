package grpcapi

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"privacyfilter/filter"
	pb "privacyfilter/gen/filterpb"
	"privacyfilter/store"
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

func TestGRPCRedactReversibleAndRestore(t *testing.T) {
	client, cleanup := newGRPCClient(t, time.Minute)
	defer cleanup()

	redacted, err := client.RedactReversible(context.Background(), &pb.RedactRequest{
		Text: "邮箱 a@b.com 手机 13900001111",
	})
	if err != nil {
		t.Fatalf("RedactReversible: %v", err)
	}
	if redacted.GetSessionId() == "" {
		t.Fatal("session_id is empty")
	}
	if redacted.GetRedacted() != "邮箱 [邮箱_0] 手机 [电话_0]" {
		t.Fatalf("redacted=%q", redacted.GetRedacted())
	}
	if len(redacted.GetEntities()) != 2 || redacted.GetEntities()[0].GetPlaceholder() != "[邮箱_0]" {
		t.Fatalf("entities missing placeholders: %#v", redacted.GetEntities())
	}

	textResp, err := client.Restore(context.Background(), &pb.RestoreRequest{
		SessionId: redacted.GetSessionId(),
		Payload:   &pb.RestoreRequest_Text{Text: "发给 [邮箱_0]"},
	})
	if err != nil {
		t.Fatalf("Restore text: %v", err)
	}
	if textResp.GetRestored() != "发给 a@b.com" {
		t.Fatalf("restored=%q", textResp.GetRestored())
	}

	jsonResp, err := client.Restore(context.Background(), &pb.RestoreRequest{
		SessionId: redacted.GetSessionId(),
		Payload:   &pb.RestoreRequest_Json{Json: `{"to":"[邮箱_0]","phone":"[电话_0]","count":2}`},
	})
	if err != nil {
		t.Fatalf("Restore json: %v", err)
	}
	gotJSON := jsonResp.GetJson()
	for _, want := range []string{`"to":"a@b.com"`, `"phone":"13900001111"`, `"count":2`} {
		if !strings.Contains(gotJSON, want) {
			t.Fatalf("restored json missing %s: %s", want, gotJSON)
		}
	}
}

func TestGRPCRestoreMissingSession(t *testing.T) {
	client, cleanup := newGRPCClient(t, time.Minute)
	defer cleanup()

	_, err := client.Restore(context.Background(), &pb.RestoreRequest{
		SessionId: "missing",
		Payload:   &pb.RestoreRequest_Text{Text: "[邮箱_0]"},
	})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("Restore error=%v want NotFound", err)
	}
}

func newGRPCClient(t *testing.T, ttl time.Duration) (pb.PrivacyFilterClient, func()) {
	t.Helper()
	pf, err := filter.New("../../rules/gitleaks.toml")
	if err != nil {
		t.Fatalf("filter.New: %v", err)
	}

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	RegisterWithStore(srv, pf, store.NewMemoryStore(), ttl)
	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		srv.Stop()
		t.Fatalf("dial: %v", err)
	}
	cleanup := func() {
		_ = conn.Close()
		srv.Stop()
	}
	return pb.NewPrivacyFilterClient(conn), cleanup
}
