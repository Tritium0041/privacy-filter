package filter

import "regexp"

// 结构化 PII 正则。Go 的 regexp 是 RE2，不支持前后向断言，
// 因此数字边界用 digitBounded / ipBounded 在匹配后手工校验。
var (
	reEmail    = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	rePhoneCN  = regexp.MustCompile(`(?:\+?86[-\s]?)?1[3-9][0-9]{9}`)
	reIDCard   = regexp.MustCompile(`[1-9][0-9]{16}[0-9Xx]`)
	reBankCard = regexp.MustCompile(`[0-9]{13,19}`)
	reIPv4     = regexp.MustCompile(`(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])`)
)

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// digitBounded 校验匹配两侧不是数字（替代 RE2 没有的前后向断言）。
func digitBounded(text string, start, end int) bool {
	if start > 0 && isDigit(text[start-1]) {
		return false
	}
	if end < len(text) && isDigit(text[end]) {
		return false
	}
	return true
}

// ipBounded 校验匹配两侧不是数字或点。
func ipBounded(text string, start, end int) bool {
	if start > 0 && (isDigit(text[start-1]) || text[start-1] == '.') {
		return false
	}
	if end < len(text) && (isDigit(text[end]) || text[end] == '.') {
		return false
	}
	return true
}

// luhnValid 做 Luhn 校验，过滤掉「长得像卡号的普通数字串」。
func luhnValid(num string) bool {
	sum := 0
	double := false
	for i := len(num) - 1; i >= 0; i-- {
		d := int(num[i] - '0')
		if double {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// detectPII 返回结构化 PII 的命中区间。
func detectPII(text string) []span {
	var spans []span
	for _, m := range reEmail.FindAllStringIndex(text, -1) {
		spans = append(spans, span{m[0], m[1], "[邮箱]"})
	}
	for _, m := range rePhoneCN.FindAllStringIndex(text, -1) {
		if digitBounded(text, m[0], m[1]) {
			spans = append(spans, span{m[0], m[1], "[电话]"})
		}
	}
	for _, m := range reIDCard.FindAllStringIndex(text, -1) {
		if digitBounded(text, m[0], m[1]) {
			spans = append(spans, span{m[0], m[1], "[身份证]"})
		}
	}
	for _, m := range reIPv4.FindAllStringIndex(text, -1) {
		if ipBounded(text, m[0], m[1]) {
			spans = append(spans, span{m[0], m[1], "[IP]"})
		}
	}
	for _, m := range reBankCard.FindAllStringIndex(text, -1) {
		if digitBounded(text, m[0], m[1]) && luhnValid(text[m[0]:m[1]]) {
			spans = append(spans, span{m[0], m[1], "[银行卡]"})
		}
	}
	return spans
}
