# Privacy Filter — 隐私过滤（Go）

[English](README.md) | **简体中文**

在文本进入 LLM 之前，过滤掉用户的敏感信息（PII / 密钥）。
纯 Go、无模型、无 GPU、无 CGO —— 单个静态二进制，任何长度文本都是毫秒级。

🌐 官网使用：[PackyCode](https://www.packyapi.com) —— API 中转服务的隐私合规组件

---

## 四种用法

1. **核心包**：网关直接 `import "privacyfilter/filter"`，过滤是一次函数调用，无 HTTP 跳转。
2. **HTTP 服务**：`cmd/http`，REST 接口。
3. **gRPC 服务**：`cmd/grpc`，接口见 `proto/filter.proto`。
4. **示例反向代理**：`cmd/gateway`，转发 LLM 请求前脱敏，上游响应返回前自动还原占位符。

后两个都只是核心包 `filter` 的薄封装。

---

## 两层检测

| 层 | 负责 | 技术 |
|---|---|---|
| 结构化 PII | 邮箱、手机号、身份证、银行卡（Luhn 校验）、IP | 正则 |
| 密钥 / 凭证 | API key、token、私钥、句子里的口令、未知高熵随机串 | gitleaks 规则集（关键词预筛）+ 上下文正则 + 香农熵兜底 |

各层产出 `(起点, 终点, 占位符)` 区间 → 合并去重叠 → 单遍重建文本。
占位符带类型（`[邮箱] [电话] [身份证] [银行卡] [IP] [密钥]`），不可逆（不还原）。

> 不含人名/地名/机构识别 —— 那类需要 NER 模型，CPU 上对长文本要数秒，已按需求移除。
> 高危身份信息（身份证/银行卡/密钥等）全部由正则覆盖。

---

## 目录结构

```
privacy-filter/
├── go.mod / go.sum
├── filter/                  核心包（可被网关直接 import）
│   ├── filter.go            Filter / New / Redact
│   ├── pii.go               结构化 PII
│   ├── secrets.go           gitleaks + 上下文 + 熵
│   └── filter_test.go
├── cmd/
│   ├── http/main.go         HTTP 服务
│   ├── grpc/main.go         gRPC 服务
│   └── gateway/main.go      示例反向代理网关
├── proto/filter.proto       gRPC 接口定义
├── gen/filterpb/            protoc 生成的代码
├── rules/gitleaks.toml      gitleaks 规则集
├── scripts/fetch_rules.sh   规则更新脚本
└── Dockerfile
```

---

## 构建

```bash
go build -o bin/server-http ./cmd/http
go build -o bin/server-grpc ./cmd/grpc
go build -o bin/privacy-gateway ./cmd/gateway
go test ./...                          # 跑全部测试
```

---

## 用法

### 1. 核心包（推荐网关用这个）

```go
import "privacyfilter/filter"

// 启动时创建一次，并发安全，可全局复用
f, err := filter.New("rules/gitleaks.toml")   // 传 "" 则用内置兜底规则

// 每个请求
res := f.Redact(userPrompt)
forwardToLLM(res.Redacted)                    // 用脱敏后的文本转发给 LLM
```

`filter.Result`：`Redacted`（脱敏后文本）、`Hit`、`Count`、`Entities`（命中明细，
含类型与字节偏移）。

如果 Agent / Tool Call 场景需要可逆占位符：

```go
res := f.RedactReversible("email a@b.com")
// res.Redacted == "email [邮箱_0]"
// res.Mapping  == map[string]string{"[邮箱_0]": "a@b.com"}

toolArgs := filter.RestoreText(`{"to":"[邮箱_0]"}`, res.Mapping)
_ = toolArgs // {"to":"a@b.com"}
```

> 从你自己的网关模块引用本包：放进同一个 monorepo，或在网关的 go.mod 里加
> `replace privacyfilter => ../privacy-filter`。`filter` 包只依赖 `BurntSushi/toml`。

### 2. HTTP 服务

```bash
./bin/server-http                    # 默认 :8088
```

```bash
curl http://127.0.0.1:8088/health
curl -X POST http://127.0.0.1:8088/redact -H 'Content-Type: application/json' \
  -d '{"text":"我的邮箱是 a@b.com，密码是 Hunter2xy"}'
# {"redacted":"我的邮箱是 [邮箱]，密码是 [密钥]","hit":true,"count":2,"entities":[...],"elapsed_ms":0.08}
```

可逆脱敏：

```bash
curl -X POST http://127.0.0.1:8088/redact_reversible -H 'Content-Type: application/json' \
  -d '{"text":"email a@b.com"}'
# {"redacted":"email [邮箱_0]","session_id":"...","hit":true,"count":1,"entities":[...],"elapsed_ms":0.08}

curl -X POST http://127.0.0.1:8088/restore -H 'Content-Type: application/json' \
  -d '{"session_id":"...","text":"send to [邮箱_0]"}'
# {"restored":"send to a@b.com"}

curl -X POST http://127.0.0.1:8088/restore -H 'Content-Type: application/json' \
  -d '{"session_id":"...","json":{"to":"[邮箱_0]"}}'
# {"json":{"to":"a@b.com"}}
```

接口：`GET /health`、`POST /redact`、`POST /redact/batch`（`{"texts":[...]}`）、
`POST /redact_reversible`、`POST /restore`。

### 3. gRPC 服务

```bash
./bin/server-grpc                    # 默认 :8089
```

服务 `filter.v1.PrivacyFilter`，方法 `Redact`、`RedactBatch`、`RedactReversible`、`Restore`，
定义见 `proto/filter.proto`。
网关侧用该 proto 生成客户端即可。重新生成本仓代码：

```bash
protoc -I. --go_out=. --go_opt=module=privacyfilter \
       --go-grpc_out=. --go-grpc_opt=module=privacyfilter proto/filter.proto
```

---

### 4. 示例反向代理网关

`cmd/gateway` 是一个可运行的隐私网关示例。它会把请求反向代理到上游 LLM API，
转发前对文本类 request body 做可逆脱敏，上游 response 返回前自动把占位符还原给客户端。

```bash
PF_GATEWAY_UPSTREAM=https://api.openai.com \
PF_GATEWAY_PORT=8090 \
go run ./cmd/gateway
```

把 OpenAI 兼容客户端的 base URL 指到 `http://127.0.0.1:8090`，路径仍然使用原来的
`/v1/responses` 等路径。`Authorization` 等大多数请求头会继续透传给上游。

该网关针对 OpenAI Responses 流式输出做了 SSE 处理：当请求使用 `stream=true`、
响应为 `text/event-stream` 时，它会边读边转发，并在 `*.delta` 事件里还原占位符，
包括 `response.output_text.delta` 和 function-call arguments delta。为了处理上游把
`[邮箱_0]` 拆到多个 chunk 的情况，代理会保留最多一个占位符长度的尾部缓冲。

非流式 JSON/text 响应会整包还原。二进制或压缩 body 会跳过，不做修改。

网关日志按 request id 串联。每个请求会优先沿用传入的 `X-Request-ID`，否则自动生成，
并通过 `X-Privacy-Gateway-Request-ID` 响应头返回。默认日志包含请求/响应元信息、
脱敏数量、占位符摘要、SSE 事件统计和代理错误，不记录原始 body。日志默认追加写入当前
工作目录的 `privacy-gateway.log`，同时也输出到 stderr。只有本地排查时再开启 body 日志：

```bash
PF_GATEWAY_LOG_LEVEL=debug \
PF_GATEWAY_DEBUG_BODY=1 \
PF_GATEWAY_LOG_BODY_BYTES=8192 \
PF_GATEWAY_UPSTREAM=https://api.openai.com \
go run ./cmd/gateway
```

---

## 配置（环境变量）

| 变量 | 默认 | 说明 |
|---|---|---|
| `PF_PORT` | `8088` | HTTP 监听端口 |
| `PF_GRPC_PORT` | `8089` | gRPC 监听端口 |
| `PF_GATEWAY_PORT` | `8090` | 示例反向代理监听端口 |
| `PF_GATEWAY_UPSTREAM` | 必填 | `cmd/gateway` 上游基础地址，例如 `https://api.openai.com` |
| `PF_GATEWAY_LOG_FILE` | `privacy-gateway.log` | 网关日志文件路径；相对路径基于当前工作目录 |
| `PF_GATEWAY_LOG_LEVEL` | `info` | 网关日志级别：`error`、`info`、`debug`、`trace` |
| `PF_GATEWAY_DEBUG_BODY` | 关闭 | 设为 `1` 后记录转换后的请求/响应 body；可能包含还原后的敏感数据 |
| `PF_GATEWAY_LOG_BODY_BYTES` | `4096` | 开启 body 日志时，单条 body 日志最多记录的字节数 |
| `PF_GATEWAY_BYPASS_MARKER` | 关闭 | 设置后，含有该字符串的 Codex session 请求会让该 session 后续都跳过请求脱敏和响应还原 |
| `PF_DISABLE_ENTROPY_FALLBACK` | 网关默认 `true` | 在 `cmd/gateway` 中关闭通用高熵兜底；gitleaks 明确规则和 `api_key`/`password` 上下文规则仍会运行 |
| `PF_GITLEAKS_TOML` | `rules/gitleaks.toml` | gitleaks 规则文件路径 |
| `PF_SESSION_TTL` | `5m` | 可逆脱敏 session 生命周期，Go duration 格式 |

---

## 性能（本机 benchmark，合成的高密度 PII 文本，属最坏情况）

| 文本长度 | 耗时 |
|---|---|
| ~50 B | ~0.01ms |
| ~2 KB | ~0.46ms |
| ~32 KB | ~9ms |

两层都是 O(n)。真实 prompt（PII 没这么密）会更快。

---

## 对接建议（网关侧）

- 用核心包 import 的方式，没有 HTTP/gRPC 跳转，也就没有超时与 fail-open/closed 问题。
- 若用 HTTP/gRPC 服务：设 150–300ms 超时；失败时建议 fail-closed（拒绝请求而非放行原文）。
- 可逆 session 只存在内存中、短期有效，HTTP/gRPC 不返回完整映射表。
  不要把 `session_id` 和用户原文或工具调用参数一起记录到日志。

---

## 备注

- gitleaks 规则在 Go 下 **222 条全部原生编译**（Go 的 `regexp` 即 RE2，与 gitleaks 同源；
  早先 Python 版因 RE2 专有语法丢了 26 条）。
- Go `regexp` 线性时间，无灾难性回溯（ReDoS）风险。
- gitleaks 不支持前后向断言，手机号/身份证等的数字边界用匹配后手工校验实现。
- 不识别人名/地名/机构。若日后要补，建议走规则（中文地址正则可行；人名宜上下文锚定）。
- 高熵兜底会误伤 git SHA、长 base64 串等 —— 可调阈值或加白名单。
