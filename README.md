# Privacy Filter — 隐私过滤（Go）

在文本进入 LLM 之前，过滤掉用户的敏感信息（PII / 密钥）。
纯 Go、无模型、无 GPU、无 CGO —— 单个静态二进制，任何长度文本都是毫秒级。

## 三种用法

1. **核心包**：网关直接 `import "privacyfilter/filter"`，过滤是一次函数调用，无 HTTP 跳转。
2. **HTTP 服务**：`cmd/http`，REST 接口。
3. **gRPC 服务**：`cmd/grpc`，接口见 `proto/filter.proto`。

后两个都只是核心包 `filter` 的薄封装。

## 两层检测

| 层 | 负责 | 技术 |
|---|---|---|
| 结构化 PII | 邮箱、手机号、身份证、银行卡（Luhn 校验）、IP | 正则 |
| 密钥 / 凭证 | API key、token、私钥、句子里的口令、未知高熵随机串 | gitleaks 规则集（关键词预筛）+ 上下文正则 + 香农熵兜底 |

各层产出 `(起点, 终点, 占位符)` 区间 → 合并去重叠 → 单遍重建文本。
占位符带类型（`[邮箱] [电话] [身份证] [银行卡] [IP] [密钥]`），不可逆（不还原）。

> 不含人名/地名/机构识别 —— 那类需要 NER 模型，CPU 上对长文本要数秒，已按需求移除。
> 高危身份信息（身份证/银行卡/密钥等）全部由正则覆盖。

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
│   └── grpc/main.go         gRPC 服务
├── proto/filter.proto       gRPC 接口定义
├── gen/filterpb/            protoc 生成的代码
├── rules/gitleaks.toml      gitleaks 规则集
├── scripts/fetch_rules.sh   规则更新脚本
└── Dockerfile
```

## 构建

```bash
go build -o bin/server-http ./cmd/http
go build -o bin/server-grpc ./cmd/grpc
go test ./...                          # 跑全部测试
```

## 用法 1：核心包（推荐网关用这个）

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

> 从你自己的网关模块引用本包：放进同一个 monorepo，或在网关的 go.mod 里加
> `replace privacyfilter => ../privacy-filter`。`filter` 包只依赖 `BurntSushi/toml`。

## 用法 2：HTTP 服务

```bash
./bin/server-http                    # 默认 :8088
```

```bash
curl http://127.0.0.1:8088/health
curl -X POST http://127.0.0.1:8088/redact -H 'Content-Type: application/json' \
  -d '{"text":"我的邮箱是 a@b.com，密码是 Hunter2xy"}'
# {"redacted":"我的邮箱是 [邮箱]，密码是 [密钥]","hit":true,"count":2,"entities":[...],"elapsed_ms":0.08}
```

接口：`GET /health`、`POST /redact`、`POST /redact/batch`（`{"texts":[...]}`）。

## 用法 3：gRPC 服务

```bash
./bin/server-grpc                    # 默认 :8089
```

服务 `filter.v1.PrivacyFilter`，方法 `Redact` / `RedactBatch`，定义见 `proto/filter.proto`。
网关侧用该 proto 生成客户端即可。重新生成本仓代码：

```bash
protoc -I. --go_out=. --go_opt=module=privacyfilter \
       --go-grpc_out=. --go-grpc_opt=module=privacyfilter proto/filter.proto
```

## 配置（环境变量）

| 变量 | 默认 | 说明 |
|---|---|---|
| `PF_PORT` | `8088` | HTTP 监听端口 |
| `PF_GRPC_PORT` | `8089` | gRPC 监听端口 |
| `PF_GITLEAKS_TOML` | `rules/gitleaks.toml` | gitleaks 规则文件路径 |

## 性能（本机 benchmark，合成的高密度 PII 文本，属最坏情况）

| 文本长度 | 耗时 |
|---|---|
| ~50 B | ~0.01ms |
| ~2 KB | ~0.46ms |
| ~32 KB | ~9ms |

两层都是 O(n)。真实 prompt（PII 没这么密）会更快。

## 对接建议（网关侧）

- 用核心包 import 的方式，没有 HTTP/gRPC 跳转，也就没有超时与 fail-open/closed 问题。
- 若用 HTTP/gRPC 服务：设 150–300ms 超时；失败时建议 fail-closed（拒绝请求而非放行原文）。

## 备注

- gitleaks 规则在 Go 下 **222 条全部原生编译**（Go 的 `regexp` 即 RE2，与 gitleaks 同源；
  早先 Python 版因 RE2 专有语法丢了 26 条）。
- Go `regexp` 线性时间，无灾难性回溯（ReDoS）风险。
- gitleaks 不支持前后向断言，手机号/身份证等的数字边界用匹配后手工校验实现。
- 不识别人名/地名/机构。若日后要补，建议走规则（中文地址正则可行；人名宜上下文锚定）。
- 高熵兜底会误伤 git SHA、长 base64 串等 —— 可调阈值或加白名单。
