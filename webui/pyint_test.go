package webui

import (
	"strings"
	"testing"
)

// pydantic 2.13's int from a form string: the value, or the error type
// (vectors from TypeAdapter(int).validate_python).
func TestIntsParseAsPydanticParsesThem(t *testing.T) {
	cases := map[string]string{
		" 8080 ":                         "8080",
		"8_080":                          "8080",
		"8__0":                           "int_parsing",
		"1.0":                            "1",
		"1.5":                            "int_parsing",
		"+5":                             "5",
		"-5":                             "-5",
		"0x10":                           "int_parsing",
		"\uff11\uff12":                   "int_parsing",
		"1e3":                            "int_parsing",
		"  ":                             "int_parsing",
		"99999999999999999999999":        "99999999999999999999999",
		"1_":                             "int_parsing",
		"\u0663":                         "int_parsing",
		"\t7\n":                          "7",
		"007":                            "7",
		"-0":                             "0",
		"1.":                             "int_parsing",
		".5":                             "int_parsing",
		"1.0000":                         "1",
		"+_1":                            "int_parsing",
		"-_1":                            "int_parsing",
		"_1":                             "int_parsing",
		"1_0.0":                          "10",
		"1.0_0":                          "int_parsing",
		"1.00":                           "1",
		"10.":                            "int_parsing",
		"+1.0":                           "1",
		"-1.0":                           "-1",
		"1. ":                            "int_parsing",
		".0":                             "int_parsing",
		"1..0":                           "int_parsing",
		"1.0.0":                          "int_parsing",
		"\u00a07":                        "7",
		"\u20037":                        "7",
		"\u2028 7":                       "7",
		"\u001c7":                        "int_parsing",
		"\u001f7":                        "int_parsing",
		"\u00857":                        "7",
		"7\u001c":                        "int_parsing",
		"1 0":                            "int_parsing",
		"0_0":                            "0",
		"00":                             "0",
		"-00":                            "0",
		"+-1":                            "int_parsing",
		"1-":                             "int_parsing",
		"1+":                             "int_parsing",
		"1.0e0":                          "int_parsing",
		"  -  1":                         "int_parsing",
		"-":                              "int_parsing",
		"+":                              "int_parsing",
		"1\u0000":                        "int_parsing",
		"9223372036854775807":            "9223372036854775807",
		"9223372036854775808":            "9223372036854775808",
		"-9223372036854775809":           "-9223372036854775809",
		"100000000000000000.0":           "100000000000000000",
		"_":                              "int_parsing",
		"1__":                            "int_parsing",
		"1_2_3":                          "123",
		"\u0660\u0660":                   "int_parsing",
		"1.0 0":                          "int_parsing",
		"1 .0":                           "int_parsing",
		"1.0\t":                          "1",
		"27015.0":                        "27015",
		"2_222":                          "2222",
		" 2_222 ":                        "2222",
		"0443":                           "443",
		strings.Repeat("1", 4301):        "int_parsing_size",
		strings.Repeat("1_", 2200) + "1": "ok",
		"-" + strings.Repeat("1", 4300):  "int_parsing_size",
		strings.Repeat("1", 4300) + ".0": "ok",
		strings.Repeat("0", 4300) + strings.Repeat("1", 4300): "ok",
		strings.Repeat("1", 4300):                             "ok",
	}
	for text, want := range cases {
		n, kind := pyIntResult(text)
		got := kind
		if kind == "" {
			got = n.String()
			if len(text) > 100 {
				got = "ok"
			}
		}
		if got != want {
			t.Errorf("%q: %s, want %s", text, got, want)
		}
	}
}
