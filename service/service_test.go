package service

import (
	"testing"

	"ip-query/model"
)

func TestIsIPAndDetectIPVersion(t *testing.T) {
	cases := []struct {
		input   string
		isIP    bool
		version string
	}{
		{input: "8.8.8.8", isIP: true, version: "IPv4"},
		{input: "2001:4860:4860::8888", isIP: true, version: "IPv6"},
		{input: "example.com", isIP: false, version: "unknown"},
	}

	for _, tc := range cases {
		if got := IsIP(tc.input); got != tc.isIP {
			t.Fatalf("IsIP(%q) = %v", tc.input, got)
		}
		if got := DetectIPVersion(tc.input); got != tc.version {
			t.Fatalf("DetectIPVersion(%q) = %q", tc.input, got)
		}
	}
}

func TestASNParsing(t *testing.T) {
	if got := normalizeASN(" 13335 "); got != "AS13335" {
		t.Fatalf("normalizeASN() = %q", got)
	}
	if got := parseASNNumber("AS13335"); got != 13335 {
		t.Fatalf("parseASNNumber() = %d", got)
	}
	if got := extractASNumber("AS15169 Google LLC"); got != "AS15169" {
		t.Fatalf("extractASNumber() = %q", got)
	}
	if got := extractASOrg("AS15169 Google LLC"); got != "Google LLC" {
		t.Fatalf("extractASOrg() = %q", got)
	}
}

func TestAnalyzeBrowserNATSymmetricCandidate(t *testing.T) {
	req := model.BrowserNATReportRequest{
		Candidates: []model.ICECandidateInfo{
			{Type: "host", Address: "192.168.1.2", Port: 5000},
			{Type: "srflx", Address: "198.51.100.10", Port: 40000, RelatedAddress: "192.168.1.2", RelatedPort: 5000},
			{Type: "srflx", Address: "198.51.100.10", Port: 40001, RelatedAddress: "192.168.1.2", RelatedPort: 5000},
		},
		SelectedCandidateType:  "srflx",
		SelectedLocalCandidate: model.ICECandidateInfo{Type: "srflx", Address: "198.51.100.10", Port: 40000},
		ICEConnectionState:     "connected",
	}

	got := AnalyzeBrowserNAT(req, "en")
	if got.TypeCode != "symmetric" {
		t.Fatalf("TypeCode = %q", got.TypeCode)
	}
	if got.HasNAT == nil || !*got.HasNAT {
		t.Fatalf("HasNAT = %#v", got.HasNAT)
	}
	if !got.IPv4Supported || got.IPv6Supported {
		t.Fatalf("IPv4Supported=%v IPv6Supported=%v", got.IPv4Supported, got.IPv6Supported)
	}
}
