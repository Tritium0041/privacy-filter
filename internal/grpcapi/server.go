// Package grpcapi 把 *filter.Filter 包成 gRPC 服务。
package grpcapi

import (
	"context"
	"time"

	"google.golang.org/grpc"

	"privacyfilter/filter"
	pb "privacyfilter/gen/filterpb"
)

type server struct {
	pb.UnimplementedPrivacyFilterServer
	f *filter.Filter
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

// toProto 把 filter.Result 转成 gRPC 响应。
func toProto(res filter.Result, t0 time.Time) *pb.RedactResponse {
	ents := make([]*pb.Entity, len(res.Entities))
	for i, e := range res.Entities {
		ents[i] = &pb.Entity{
			Type:  e.Type,
			Start: int32(e.Start),
			End:   int32(e.End),
			Text:  e.Text,
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

// Register 把过滤服务注册到给定的 gRPC server。
func Register(s *grpc.Server, f *filter.Filter) {
	pb.RegisterPrivacyFilterServer(s, &server{f: f})
}
