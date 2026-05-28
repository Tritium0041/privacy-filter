package filter

import (
	"fmt"
	"strings"
	"testing"
)

func newFilter(t *testing.T) *Filter {
	t.Helper()
	f, err := New("../rules/gitleaks.toml")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return f
}

func redact(t *testing.T, f *Filter, text string) string {
	t.Helper()
	return f.Redact(text).Redacted
}

// --- 结构化 PII ---

func TestEmail(t *testing.T) {
	f := newFilter(t)
	if got := redact(t, f, "有事联系 test.user@example.com 谢谢"); !strings.Contains(got, "[邮箱]") {
		t.Errorf("邮箱未脱敏: %q", got)
	}
}

func TestPhoneCN(t *testing.T) {
	f := newFilter(t)
	if got := redact(t, f, "我的手机是 13812345678 随时打"); !strings.Contains(got, "[电话]") {
		t.Errorf("手机号未脱敏: %q", got)
	}
}

func TestIDCard(t *testing.T) {
	f := newFilter(t)
	if got := redact(t, f, "身份证号 11010519900307743X 务必保密"); !strings.Contains(got, "[身份证]") {
		t.Errorf("身份证未脱敏: %q", got)
	}
}

func TestBankCardValidLuhn(t *testing.T) {
	f := newFilter(t)
	if got := redact(t, f, "付款卡号 4111111111111111"); !strings.Contains(got, "[银行卡]") {
		t.Errorf("银行卡未脱敏: %q", got)
	}
}

func TestBankCardInvalidLuhnIgnored(t *testing.T) {
	f := newFilter(t)
	if got := redact(t, f, "订单编号 1234567890123456"); strings.Contains(got, "[银行卡]") {
		t.Errorf("Luhn 不通过的数字串被误判成银行卡: %q", got)
	}
}

// --- 密钥层 ---

func TestGitleaksRulesLoaded(t *testing.T) {
	f := newFilter(t)
	rules, skipped := f.Stats()
	if rules <= 100 {
		t.Errorf("gitleaks 规则只加载了 %d 条（应上百条）", rules)
	}
	t.Logf("gitleaks 规则 %d 条，跳过 %d 条", rules, skipped)
}

func TestContextPassword(t *testing.T) {
	f := newFilter(t)
	if got := redact(t, f, "我的密码是 Hunter2xyz"); !strings.Contains(got, "[密钥]") {
		t.Errorf("上下文口令未脱敏: %q", got)
	}
}

func TestContextAPIKey(t *testing.T) {
	f := newFilter(t)
	if got := redact(t, f, "配置里 api_key = aB3xK9pLmN2qR7sT"); !strings.Contains(got, "[密钥]") {
		t.Errorf("api_key 未脱敏: %q", got)
	}
}

func TestEntropyFallback(t *testing.T) {
	f := newFilter(t)
	if got := redact(t, f, "临时凭证 aB3xK9pLmN2qR7sT5vW1zY 已生成"); !strings.Contains(got, "[密钥]") {
		t.Errorf("高熵随机串未脱敏: %q", got)
	}
}

// --- 整体行为 ---

func TestCleanTextNoHit(t *testing.T) {
	f := newFilter(t)
	text := "今天天气不错，我们一起去公园散步吧。"
	res := f.Redact(text)
	if res.Redacted != text || res.Hit || res.Count != 0 {
		t.Errorf("干净文本被误改: %+v", res)
	}
}

func TestMultipleEntities(t *testing.T) {
	f := newFilter(t)
	res := f.Redact("邮箱 a@b.com 手机 13900001111 密码是 Qwer1234")
	if !strings.Contains(res.Redacted, "[邮箱]") ||
		!strings.Contains(res.Redacted, "[电话]") ||
		!strings.Contains(res.Redacted, "[密钥]") {
		t.Errorf("多实体脱敏不全: %q", res.Redacted)
	}
	if res.Count < 3 {
		t.Errorf("命中数 %d，应 >= 3", res.Count)
	}
}

func TestBuiltinFallback(t *testing.T) {
	f, err := New("") // 空路径 → 用内置兜底规则
	if err != nil {
		t.Fatalf("New(\"\"): %v", err)
	}
	if rules, _ := f.Stats(); rules == 0 {
		t.Error("内置兜底规则为空")
	}
}

// BenchmarkRedact 测不同文本长度下的脱敏耗时。
func BenchmarkRedact(b *testing.B) {
	f, err := New("../rules/gitleaks.toml")
	if err != nil {
		b.Fatal(err)
	}
	unit := "我叫张伟，邮箱 a@b.com，密码是 Hunter2xy，卡号 4111111111111111。"
	for _, size := range []int{50, 2000, 32000} {
		text := strings.Repeat(unit, size/len(unit)+1)[:size]
		b.Run(fmt.Sprintf("%dB", len(text)), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				f.Redact(text)
			}
		})
	}
}
