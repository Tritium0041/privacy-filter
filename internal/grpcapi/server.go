// Package grpcapi 把 *filter.Filter 包成 gRPC 服务。
package grpcapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"privacyfilter/filter"
	pb "privacyfilter/gen/filterpb"
	"privacyfilter/store"
)

type server struct {
	pb.UnimplementedPrivacyFilterServer
	f        *filter.Filter
	sessions store.SessionStore
	ttl      time.Duration
}

func (s *server) Redact(_ context.Context, req *pb.RedactRequest) (*pb.RedactResponse, error) {
	t0 := time.Now()
	return toProto(s.f.Redact(req.GetText()), t0), nil
}

func (s *server) RedactBatch(_ context.Context, req *pb.RedactBatchRequest) (*pb.RedactBatchResponse, error) {
	results := make([]*pb.RedactResponse, len(req.GetTexts()))
	for i, t := range req.GetTexts() {
		t0 := time.Now()
		results[i] = toProto(s.f.Redact(t), t0)
	}
	return &pb.RedactBatchResponse{Results: results}, nil
}

func (s *server) RedactReversible(_ context.Context, req *pb.RedactRequest) (*pb.RedactReversibleResponse, error) {
	t0 := time.Now()
	res := s.f.RedactReversible(req.GetText())
	sessionID, err := s.sessions.Save(res.Mapping, s.ttl)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "save session failed: %v", err)
	}
	return toReversibleProto(res, t0, sessionID), nil
}

func (s *server) Restore(_ context.Context, req *pb.RestoreRequest) (*pb.RestoreResponse, error) {
	if req.GetSessionId() == "" {
		return nil, status.Error(codes.InvalidArgument, "session_id is required")
	}
	mapping, err := s.sessions.Load(req.GetSessionId())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrExpired) {
			return nil, status.Error(codes.NotFound, "session not found")
		}
		return nil, status.Errorf(codes.Internal, "load session failed: %v", err)
	}

	switch req.GetPayload().(type) {
	case *pb.RestoreRequest_Text:
		return &pb.RestoreResponse{
			Payload: &pb.RestoreResponse_Restored{Restored: filter.RestoreText(req.GetText(), mapping)},
		}, nil
	case *pb.RestoreRequest_Json:
		var payload any
		dec := json.NewDecoder(bytes.NewBufferString(req.GetJson()))
		dec.UseNumber()
		if err := dec.Decode(&payload); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid json payload: %v", err)
		}
		restored, err := filter.RestoreJSON(payload, mapping)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid json payload: %v", err)
		}
		out, err := json.Marshal(restored)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "marshal restored json failed: %v", err)
		}
		return &pb.RestoreResponse{
			Payload: &pb.RestoreResponse_Json{Json: string(out)},
		}, nil
	default:
		return nil, status.Error(codes.InvalidArgument, "text or json payload is required")
	}
}

// toProto 把 filter.Result 转成 gRPC 响应。
func toProto(res filter.Result, t0 time.Time) *pb.RedactResponse {
	ents := make([]*pb.Entity, len(res.Entities))
	for i, e := range res.Entities {
		ents[i] = &pb.Entity{
			Type:        e.Type,
			Start:       int32(e.Start),
			End:         int32(e.End),
			Text:        e.Text,
			Placeholder: e.Placeholder,
		}
	}
	return &pb.RedactResponse{
		Redacted:  res.Redacted,
		Hit:       res.Hit,
		Count:     int32(res.Count),
		Entities:  ents,
		ElapsedMs: float64(time.Since(t0).Microseconds()) / 1000.0,
	}
}

func toReversibleProto(res filter.ReversibleResult, t0 time.Time, sessionID string) *pb.RedactReversibleResponse {
	ents := make([]*pb.Entity, len(res.Entities))
	for i, e := range res.Entities {
		ents[i] = &pb.Entity{
			Type:        e.Type,
			Start:       int32(e.Start),
			End:         int32(e.End),
			Text:        e.Text,
			Placeholder: e.Placeholder,
		}
	}
	return &pb.RedactReversibleResponse{
		Redacted:  res.Redacted,
		Hit:       res.Hit,
		Count:     int32(res.Count),
		Entities:  ents,
		ElapsedMs: float64(time.Since(t0).Microseconds()) / 1000.0,
		SessionId: sessionID,
	}
}

// Register 把过滤服务注册到给定的 gRPC server。
func Register(s *grpc.Server, f *filter.Filter) {
	RegisterWithStore(s, f, store.NewMemoryStore(), store.DefaultTTL)
}

// RegisterWithStore 把过滤服务注册到给定的 gRPC server，并启用可逆脱敏 session。
func RegisterWithStore(s *grpc.Server, f *filter.Filter, sessions store.SessionStore, ttl time.Duration) {
	pb.RegisterPrivacyFilterServer(s, &server{f: f, sessions: sessions, ttl: ttl})
}
