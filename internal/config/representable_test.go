package config

import (
	"bytes"
	"strings"
	"testing"
)

// TestRepresentableAgreesWithTheActualWriteThenReadRoundTrip 把谓词钉死在它宣称的性质上：
// 每个判为可表示的值都必须真的满足 parseValue(quote(v)) == v。线格式没有转义机制，读取器又会
// 顺序剥离一层双引号再剥离一层单引号（见 quote_drift_test.go），所以“自身首尾恰为一对单引号”
// 的值写出后必然少一层，只能判为不可表示。
func TestRepresentableAgreesWithTheActualWriteThenReadRoundTrip(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
		want  bool
	}{
		{name: "ordinary value", value: "web1", want: true},
		{name: "only single quotes", value: "it's", want: true},
		{name: "only double quotes", value: `say "hi"`, want: true},
		{name: "leading and trailing spaces", value: "  padded  ", want: true},
		{name: "lone single quote", value: "'", want: true},
		{name: "lone double quote", value: `"`, want: true},
		{name: "empty", value: "", want: true},
		{name: "inline comment shape", value: "web1 # prod", want: true},
		{name: "embedded hash", value: "web#1", want: true},
		{name: "single quote wrapped word", value: "'x'", want: false},
		{name: "single quote wrapped empty", value: "''", want: false},
		{name: "single quote wrapped phrase", value: "'x y'", want: false},
		{name: "line feed", value: "trusted\nINCLUDE_PUBLIC_IP='1'", want: false},
		{name: "carriage return", value: "trusted\rforged", want: false},
		{name: "NUL", value: "trusted\x00forged", want: false},
		{name: "mixed quotes", value: `both'and"`, want: false},
		{name: "mixed quotes wrapped in single quotes", value: `'say "hi"'`, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := Representable(test.value)
			if got != test.want {
				t.Fatalf("Representable(%q) = %v, want %v", test.value, got, test.want)
			}
			if !got {
				return
			}
			// 判为真就必须经得起真实往返，否则谓词已经和线格式脱节。
			if back := parseValue(quote(test.value)); back != test.value {
				t.Fatalf("parseValue(quote(%q)) = %q, want %q", test.value, back, test.value)
			}
		})
	}
}

// TestCanonicalCollapsesInheritedQuoteLayersToAnIdempotentFixedPoint 守护“一次性收敛”：
// 继承下来的不可表示值必须在单次 Canonical 调用内落到不动点，而不是每次升级重写配置就吞掉一层引号。
func TestCanonicalCollapsesInheritedQuoteLayersToAnIdempotentFixedPoint(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
		want  string
	}{
		{name: "ordinary value untouched", value: "web1", want: "web1"},
		{name: "only single quotes untouched", value: "it's", want: "it's"},
		{name: "only double quotes untouched", value: `say "hi"`, want: `say "hi"`},
		{name: "leading and trailing spaces untouched", value: "  padded  ", want: "  padded  "},
		{name: "lone single quote untouched", value: "'", want: "'"},
		{name: "lone double quote untouched", value: `"`, want: `"`},
		{name: "empty untouched", value: "", want: ""},
		{name: "inline comment shape untouched", value: "web1 # prod", want: "web1 # prod"},
		{name: "embedded hash untouched", value: "web#1", want: "web#1"},
		{name: "one quote layer", value: "'x'", want: "x"},
		{name: "one quote layer around empty", value: "''", want: ""},
		{name: "one quote layer around phrase", value: "'x y'", want: "x y"},
		{name: "two quote layers", value: "''x''", want: "x"},
		{name: "three quote layers", value: "'''x'''", want: "x"},
		{name: "quote layer around double quotes", value: `'say "hi"'`, want: `say "hi"`},
		// 混合引号与控制字节没有任何可表示形式，Canonical 只保证停在原地不再吞引号；
		// 这类值该由 Representable/Write 拒绝，而不是被静默改写。
		{name: "mixed quotes stay put", value: `both'and"`, want: `both'and"`},
		{name: "line feed stays put", value: "trusted\nforged", want: "trusted\nforged"},
		{name: "carriage return stays put", value: "trusted\rforged", want: "trusted\rforged"},
		{name: "NUL stays put", value: "trusted\x00forged", want: "trusted\x00forged"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := Canonical(test.value)
			if got != test.want {
				t.Fatalf("Canonical(%q) = %q, want %q", test.value, got, test.want)
			}
			if again := Canonical(got); again != got {
				t.Fatalf("Canonical(%q) = %q is not a fixed point: Canonical of it = %q", test.value, got, again)
			}
			if hasUnrepresentableBytes(test.value) {
				return
			}
			if !Representable(got) {
				t.Fatalf("Canonical(%q) = %q, which Write still cannot represent", test.value, got)
			}
		})
	}
}

// TestWriteRejectsSingleQuoteWrappedValuesWithoutEmittingPartialOutput 断言写出前就失败：
// 值若会被读取器多剥一层引号，Write 必须报错，且不能留下半份配置（沿用既有 fail-closed 断言方式）。
func TestWriteRejectsSingleQuoteWrappedValuesWithoutEmittingPartialOutput(t *testing.T) {
	for _, test := range []struct {
		name, value string
	}{
		{name: "single quote wrapped word", value: "'x'"},
		{name: "single quote wrapped empty", value: "''"},
		{name: "single quote wrapped phrase", value: "'x y'"},
		{name: "two quote layers", value: "''x''"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			err := Write(&output, map[string]string{"HOST_LABEL": test.value})
			if err == nil {
				t.Fatal("value the reader would hand back differently was accepted")
			}
			if !strings.Contains(err.Error(), "cannot be represented") {
				t.Errorf("Write(%q) err = %v, want it to say the value cannot be represented", test.value, err)
			}
			if !strings.Contains(err.Error(), "HOST_LABEL") {
				t.Errorf("Write(%q) err = %v, want it to name the offending key", test.value, err)
			}
			if output.Len() != 0 {
				t.Fatalf("validation failure left partial output: %q", output.Bytes())
			}
		})
	}
}

// TestRepresentableValuesSurviveWriteAndParseForEveryShortQuoteCombination 是端到端的兜底：
// 谓词一旦对某个值说“可以”，整条 Write -> parse 链路就必须还回一模一样的字节；说“不行”的值
// 则必须在任何字节写出前被拒。穷举比手写用例更能挡住引用逻辑的细微漂移。
func TestRepresentableValuesSurviveWriteAndParseForEveryShortQuoteCombination(t *testing.T) {
	corpus := quoteCorpus()
	if len(corpus) != 259 {
		t.Fatalf("corpus holds %d values, want 259", len(corpus))
	}
	roundTripped := 0
	for _, value := range corpus {
		var output bytes.Buffer
		err := Write(&output, map[string]string{"HOST_LABEL": value})
		if !Representable(value) {
			if err == nil {
				t.Errorf("Write accepted unrepresentable %q", value)
			}
			if output.Len() != 0 {
				t.Errorf("Write(%q) left partial output: %q", value, output.Bytes())
			}
			continue
		}
		if err != nil {
			t.Fatalf("Write(%q) = %v", value, err)
		}
		cfg, err := parse(&output)
		if err != nil {
			t.Fatalf("parse after Write(%q) = %v", value, err)
		}
		if got := cfg.Get("HOST_LABEL"); got != value {
			t.Errorf("HOST_LABEL round-tripped %q as %q", value, got)
		}
		roundTripped++
	}
	// 语料若整体退化成“全不可表示”，上面的往返断言就成了空转。
	if roundTripped == 0 {
		t.Fatal("no corpus value was representable, so nothing was round-tripped")
	}
}

// TestCanonicalReachesARepresentableFixedPointForEveryShortQuoteCombination 保证迁移路径不会死循环、
// 也不会把不可表示的值交还给 Write：除混合引号外，任何输入都必须一步收敛到 Write 接受的形态。
func TestCanonicalReachesARepresentableFixedPointForEveryShortQuoteCombination(t *testing.T) {
	for _, value := range quoteCorpus() {
		got := Canonical(value)
		if again := Canonical(got); again != got {
			t.Errorf("Canonical(%q) = %q is not a fixed point: Canonical of it = %q", value, got, again)
		}
		if hasUnrepresentableBytes(value) {
			continue
		}
		if !Representable(got) {
			t.Errorf("Canonical(%q) = %q, which Write still cannot represent", value, got)
		}
	}
}

// hasUnrepresentableBytes 复述“无论怎么加工都写不出来”的两类值：换行/NUL 会伪造出新的一行，
// 混合引号则让无转义的 config_quote 无处下手。Canonical 对它们只承诺终止，不承诺可表示。
func hasUnrepresentableBytes(value string) bool {
	if strings.ContainsAny(value, "\r\n\x00") {
		return true
	}
	return strings.Contains(value, "'") && strings.Contains(value, `"`)
}

// quoteCorpusAlphabet 只收引用逻辑真正会分叉的字节：a 代表普通字节，两种引号决定 config_quote
// 的包裹方式，空格与制表符触发首尾裁剪，# 触发行内注释剥离。
var quoteCorpusAlphabet = []string{"a", "'", `"`, " ", "#", "\t"}

// quoteCorpus 穷举长度 0..3 的全部组合（1+6+36+216 = 259 个）。确定性生成，没有随机种子，
// 失败用例可以直接复现。
func quoteCorpus() []string {
	corpus := []string{""}
	shorter := []string{""}
	for length := 1; length <= 3; length++ {
		longer := make([]string, 0, len(shorter)*len(quoteCorpusAlphabet))
		for _, prefix := range shorter {
			for _, symbol := range quoteCorpusAlphabet {
				longer = append(longer, prefix+symbol)
			}
		}
		corpus = append(corpus, longer...)
		shorter = longer
	}
	return corpus
}
