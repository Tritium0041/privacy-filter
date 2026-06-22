// Package filter 在文本进入 LLM 前过滤掉 PII 与密钥。
//
// 纯正则、无模型、O(n)。Filter 编译一次后可并发安全地重复使用。
// 既可被网关直接 import 调用 filter.Redact，也可由 cmd/ 下的 HTTP/gRPC 服务包装。
package filter

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Entity 是一个被脱敏的命中项。Start/End 为 UTF-8 字节偏移。
type Entity struct {
	Type        string `json:"type"`
	Start       int    `json:"start"`
	End         int    `json:"end"`
	Text        string `json:"text"`
	Placeholder string `json:"placeholder,omitempty"`
}

// Result 是一次脱敏的结果。
type Result struct {
	Redacted string   `json:"redacted"`
	Hit      bool     `json:"hit"`
	Count    int      `json:"count"`
	Entities []Entity `json:"entities"`
}

// ReversibleResult 是一次可逆脱敏的结果。Mapping 的 key 是占位符，value 是原文。
type ReversibleResult struct {
	Result
	Mapping map[string]string `json:"mapping,omitempty"`
}

// span 是各检测层内部产出的区间。
type span struct {
	start, end int
	label      string
}

// Filter 持有编译好的规则。创建后只读，可并发安全地复用。
type Filter struct {
	secrets *secretDetector
}

// Options 控制 Filter 的检测策略。
type Options struct {
	DisableEntropyFallback bool
}

// New 创建一个 Filter。gitleaksTOML 为 gitleaks 规则文件路径；
// 传空字符串则只用内置兜底规则。文件存在但解析失败时返回 error。
func New(gitleaksTOML string) (*Filter, error) {
	return NewWithOptions(gitleaksTOML, Options{})
}

// NewWithOptions 创建一个带检测策略配置的 Filter。
func NewWithOptions(gitleaksTOML string, opts Options) (*Filter, error) {
	sd, err := newSecretDetector(gitleaksTOML)
	if err != nil {
		return nil, err
	}
	sd.disableEntropyFallback = opts.DisableEntropyFallback
	return &Filter{secrets: sd}, nil
}

// Stats 返回已加载的规则数，以及因语法不兼容被跳过的规则数。
func (f *Filter) Stats() (rules, skipped int) {
	return len(f.secrets.rules), f.secrets.skipped
}

// Redact 检测并脱敏文本。并发安全。
func (f *Filter) Redact(text string) Result {
	merged := f.detect(text)

	// 单遍扫描重建文本：merged 已按起点升序且互不重叠，O(n)
	var b strings.Builder
	prev := 0
	for _, s := range merged {
		b.WriteString(text[prev:s.start])
		b.WriteString(s.label)
		prev = s.end
	}
	b.WriteString(text[prev:])
	out := b.String()

	entities := make([]Entity, len(merged))
	for i, s := range merged {
		entities[i] = Entity{Type: s.label, Start: s.start, End: s.end, Text: text[s.start:s.end]}
	}
	return Result{
		Redacted: out,
		Hit:      len(merged) > 0,
		Count:    len(merged),
		Entities: entities,
	}
}

// RedactReversible 检测并脱敏文本，同时返回可用于 Restore 的占位符映射。
// 同一请求内，相同类型和原文会复用同一个占位符。
func (f *Filter) RedactReversible(text string) ReversibleResult {
	merged := f.detect(text)
	seen := make(map[string]string, len(merged))
	mapping := make(map[string]string, len(merged))
	counters := make(map[string]int)

	var b strings.Builder
	prev := 0
	entities := make([]Entity, len(merged))
	for i, s := range merged {
		original := text[s.start:s.end]
		key := s.label + "\x00" + original
		placeholder, ok := seen[key]
		if !ok {
			placeholder = indexedPlaceholder(s.label, counters[s.label])
			counters[s.label]++
			seen[key] = placeholder
			mapping[placeholder] = original
		}

		b.WriteString(text[prev:s.start])
		b.WriteString(placeholder)
		prev = s.end
		entities[i] = Entity{
			Type:        s.label,
			Start:       s.start,
			End:         s.end,
			Text:        original,
			Placeholder: placeholder,
		}
	}
	b.WriteString(text[prev:])

	res := Result{
		Redacted: b.String(),
		Hit:      len(merged) > 0,
		Count:    len(merged),
		Entities: entities,
	}
	return ReversibleResult{Result: res, Mapping: mapping}
}

// RestoreText 使用 mapping 将文本中的占位符替换回原文。未知占位符会保持原样。
func RestoreText(text string, mapping map[string]string) string {
	if len(mapping) == 0 || text == "" {
		return text
	}
	pairs := make([]string, 0, len(mapping)*2)
	for placeholder, original := range mapping {
		pairs = append(pairs, placeholder, original)
	}
	return strings.NewReplacer(pairs...).Replace(text)
}

// RestoreJSON 递归还原 JSON-like 结构中的字符串值，并保持数字、布尔和 null 不变。
func RestoreJSON(v any, mapping map[string]string) (any, error) {
	switch x := v.(type) {
	case nil:
		return nil, nil
	case string:
		return RestoreText(x, mapping), nil
	case bool, float64, float32, int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64, json.Number:
		return x, nil
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			restored, err := RestoreJSON(val, mapping)
			if err != nil {
				return nil, err
			}
			out[k] = restored
		}
		return out, nil
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			restored, err := RestoreJSON(val, mapping)
			if err != nil {
				return nil, err
			}
			out[i] = restored
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported JSON value type %T", v)
	}
}

func (f *Filter) detect(text string) []span {
	var spans []span
	spans = append(spans, detectPII(text)...)        // 结构化 PII
	spans = append(spans, f.secrets.detect(text)...) // 密钥 / 凭证
	return mergeSpans(spans)
}

func indexedPlaceholder(label string, idx int) string {
	if strings.HasPrefix(label, "[") && strings.HasSuffix(label, "]") {
		return strings.TrimSuffix(label, "]") + fmt.Sprintf("_%d]", idx)
	}
	return fmt.Sprintf("[%s_%d]", label, idx)
}

// mergeSpans 丢弃无效与重叠区间：按起点升序、同起点取更长者，
// 贪心保留互不重叠的区间。
func mergeSpans(spans []span) []span {
	var valid []span
	for _, s := range spans {
		if s.start >= 0 && s.start < s.end {
			valid = append(valid, s)
		}
	}
	sort.SliceStable(valid, func(i, j int) bool {
		if valid[i].start != valid[j].start {
			return valid[i].start < valid[j].start
		}
		return valid[i].end > valid[j].end
	})
	merged := make([]span, 0, len(valid))
	lastEnd := -1
	for _, s := range valid {
		if s.start >= lastEnd {
			merged = append(merged, s)
			lastEnd = s.end
		}
	}
	return merged
}
