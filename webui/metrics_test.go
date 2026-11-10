package webui

import (
	"math/big"
	"testing"

	"github.com/starsmash29/fr_os-community/config"
)

func TestMetricValuesFormatAsPython(t *testing.T) {
	huge, _ := new(big.Int).SetString("12345678901234567890", 10)
	for _, c := range []struct {
		value config.Value
		want  string
	}{
		{true, "1"}, {false, "0"}, {7, "7"}, {huge, "12345678901234567890"}, {2.5, "2.5"}, {0.0, "0.0"},
		{" 12 ", "12.0"}, {"nan", "nan"}, {"-inf", "-inf"}, {"1_000", "1000.0"},
	} {
		got, err := formatMetricValue(c.value)
		if err != nil || got != c.want {
			t.Errorf("formatMetricValue(%#v) = %q, %v", c.value, got, err)
		}
	}
	for _, v := range []config.Value{nil, "twelve", []config.Value{}, config.NewMap()} {
		if _, err := formatMetricValue(v); err == nil {
			t.Errorf("formatMetricValue(%#v) took it", v)
		}
	}
	if got := pyRound(2400.05, 1); got != 2400.1 {
		t.Errorf("round(2400.05, 1) = %v", got)
	}
}

func TestMetricsAccessFailsClosed(t *testing.T) {
	digest := "d6b5c6c3b2a3a1d4a1e8f2b0e0c3f5c8c1a0e4d2f9b7a6c5d4e3f2a1b0c9d8e7"
	section := func(v config.Value) *config.Map {
		return cmdMap("metrics", cmdMap("token_sha256", v))
	}
	for _, c := range []struct {
		raw    *config.Map
		header string
		want   metricsAccessResult
	}{
		{config.NewMap(), "Bearer x", metricsOff},
		{section(nil), "Bearer x", metricsOff},
		{cmdMap("metrics", []config.Value{}), "Bearer x", metricsOff},
		{section(big.NewInt(1)), "Bearer x", metricsDenied},
		{section("abc"), "Bearer x", metricsDenied},
		{section(digest), "", metricsDenied},
		{section(digest), "Bearer", metricsDenied},
		{section(digest), "Bearer wrong", metricsDenied},
	} {
		got, err := metricsAccess(c.raw, c.header)
		if err != nil || got != c.want {
			t.Errorf("%v %q: %v, %v", config.Repr(c.raw), c.header, got, err)
		}
	}
	// hmac.compare_digest raises on a str that isn't ASCII: a 500.
	if _, err := metricsAccess(section("é"+digest[1:]), "Bearer x"); err != errInternal {
		t.Errorf("a non-ASCII digest: %v", err)
	}
}
