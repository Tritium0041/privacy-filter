# ---- 构建 ----
FROM golang:1.23-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/server-http  ./cmd/http && \
    CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/server-grpc ./cmd/grpc

# ---- 运行 ----
FROM gcr.io/distroless/static-debian12
COPY --from=build /out/server-http /out/server-grpc /
COPY rules/ /rules/

EXPOSE 8088 8089

# 默认跑 HTTP 服务；要跑 gRPC 用：docker run ... --entrypoint /server-grpc
ENTRYPOINT ["/server-http"]
