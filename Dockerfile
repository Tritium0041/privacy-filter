# ---- 构建 ----
FROM golang:alpine AS build
ENV GO111MODULE=on CGO_ENABLED=0
ENV GOPROXY=https://goproxy.cn,direct

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -ldflags="-s -w" -o /out/server-http  ./cmd/http && \
    go build -ldflags="-s -w" -o /out/server-grpc ./cmd/grpc

# ---- 运行 ----
FROM alpine

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories
RUN apk upgrade --no-cache \
    && apk add --no-cache ca-certificates \
    && update-ca-certificates

COPY --from=build /out/server-http /out/server-grpc /
COPY rules/ /rules/

EXPOSE 8088 8089

# 默认跑 HTTP 服务；要跑 gRPC 用：docker run ... --entrypoint /server-grpc
ENTRYPOINT ["/server-http"]
