package filter

import (
	"math"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

const entropyMin = 4.0

// 上下文型口令：藏在句子里的密码/token，如「我的密码是 hunter2」「api_key: xxx」。
var reContextSecret = regexp.MustCompile(
	`(?i)(密码|口令|密钥|password|passwd|pwd|secret|token|api[_\s-]?key)\s*(?:是|为|:|：|=)\s*['"]?([^\s'"，。；;]{4,})`)

// 高熵兜底：抓不匹配任何已知格式的随机串。
var reEntropyToken = regexp.MustCompile(`[A-Za-z0-9+/=_\-]{20,}`)

type secretRule struct {
	id          string
	re          *regexp.Regexp
	keywords    []string // 已小写；空表示该规则总是参与
	entropy     float64
	secretGroup int
}

type secretDetector struct {
	rules   []secretRule
	skipped int // 因正则语法不兼容被跳过的规则数（Go RE2 下通常为 0）
}

// gitleaks.toml 的最小结构；未知字段（allowlist 等）会被忽略。
type tomlConfig struct {
	Rules []struct {
		ID          string   `toml:"id"`
		Regex       string   `toml:"regex"`
		Keywords    []string `toml:"keywords"`
		Entropy     float64  `toml:"entropy"`
		SecretGroup int      `toml:"secretGroup"`
	} `toml:"rules"`
}

func newSecretDetector(tomlPath string) (*secretDetector, error) {
	sd := &secretDetector{}
	if tomlPath == "" {
		sd.loadBuiltin()
		return sd, nil
	}
	var cfg tomlConfig
	if _, err := toml.DecodeFile(tomlPath, &cfg); err != nil {
		return nil, err
	}
	for _, r := range cfg.Rules {
		if r.Regex == "" {
			continue
		}
		re, err := regexp.Compile(r.Regex)
		if err != nil {
			sd.skipped++
			continue
		}
		kws := make([]string, len(r.Keywords))
		for i, k := range r.Keywords {
			kws[i] = strings.ToLower(k)
		}
		sd.rules = append(sd.rules, secretRule{r.ID, re, kws, r.Entropy, r.SecretGroup})
	}
	if len(sd.rules) == 0 {
		sd.loadBuiltin()
	}
	return sd, nil
}

// loadBuiltin 在 gitleaks.toml 缺失时提供一组兜底规则。
func (sd *secretDetector) loadBuiltin() {
	builtin := []struct {
		id, pat string
		kws     []string
	}{
		{"openai-key", `sk-(?:proj-)?[A-Za-z0-9_-]{20,}`, []string{"sk-"}},
		{"aws-access-key", `AKIA[0-9A-Z]{16}`, []string{"akia"}},
		{"github-token", `gh[pousr]_[A-Za-z0-9]{36,}`, []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"}},
		{"google-api-key", `AIza[0-9A-Za-z_-]{35}`, []string{"aiza"}},
		{"slack-token", `xox[baprs]-[0-9A-Za-z-]{10,}`, []string{"xox"}},
		{"jwt", `eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`, []string{"eyj"}},
		{"private-key", `-----BEGIN[A-Z ]*PRIVATE KEY-----`, []string{"private key"}},
	}
	for _, b := range builtin {
		sd.rules = append(sd.rules, secretRule{b.id, regexp.MustCompile(b.pat), b.kws, 0, 0})
	}
}

// detect 返回密钥/凭证的命中区间。
func (sd *secretDetector) detect(text string) []span {
	var spans []span
	low := strings.ToLower(text)

	// gitleaks 规则：关键词预筛 —— 只对命中关键词的规则跑正则
	for i := range sd.rules {
		r := &sd.rules[i]
		if !ruleApplies(r, low) {
			continue
		}
		for _, m := range r.re.FindAllStringSubmatchIndex(text, -1) {
			s, e := m[0], m[1]
			if g := r.secretGroup; g > 0 && 2*g+1 < len(m) && m[2*g] >= 0 {
				s, e = m[2*g], m[2*g+1]
			}
			if s < 0 || s >= e {
				continue
			}
			if r.entropy > 0 && shannonEntropy(text[s:e]) < r.entropy {
				continue // 复刻 gitleaks 的熵阈值，压低误报
			}
			spans = append(spans, span{s, e, "[密钥]"})
		}
	}
	// 上下文口令：只脱掉 value（第 2 个分组）
	for _, m := range reContextSecret.FindAllStringSubmatchIndex(text, -1) {
		if len(m) >= 6 && m[4] >= 0 {
			spans = append(spans, span{m[4], m[5], "[密钥]"})
		}
	}
	// 高熵兜底
	for _, m := range reEntropyToken.FindAllStringIndex(text, -1) {
		if shannonEntropy(text[m[0]:m[1]]) >= entropyMin {
			spans = append(spans, span{m[0], m[1], "[密钥]"})
		}
	}
	return spans
}

// ruleApplies 做关键词预筛：无关键词的规则总是参与，
// 否则文本里出现任一关键词才参与。
func ruleApplies(r *secretRule, lowText string) bool {
	if len(r.keywords) == 0 {
		return true
	}
	for _, kw := range r.keywords {
		if strings.Contains(lowText, kw) {
			return true
		}
	}
	return false
}

// shannonEntropy 按字节计算香农熵（bits/byte）。
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var freq [256]float64
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	ent := 0.0
	for _, c := range freq {
		if c > 0 {
			p := c / n
			ent -= p * math.Log2(p)
		}
	}
	return ent
}
