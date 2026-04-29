package provider

import (
	"encoding/json"
	"testing"
)

func TestIPInfoResultParsers(t *testing.T) {
	var result IPInfoResult
	data := []byte(`{"ip":"8.8.8.8","loc":"37.3860,-122.0838","org":"AS15169 Google LLC"}`)
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}

	parseIPInfoLocation(&result)
	parseIPInfoOrg(&result)

	if result.Latitude != 37.386 || result.Longitude != -122.0838 {
		t.Fatalf("location = %v,%v", result.Latitude, result.Longitude)
	}
	if result.ASN != "AS15169" || result.ASNNumber != 15169 || result.ASNOrganization != "Google LLC" {
		t.Fatalf("asn fields = %#v", result)
	}
}

func TestIPDataResultNormalizedASN(t *testing.T) {
	var result IPDataResult
	data := []byte(`{"ip":"8.8.8.8","asn":{"asn":"15169","name":"Google LLC"}}`)
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}

	if got := result.NormalizedASN(); got != "AS15169" {
		t.Fatalf("NormalizedASN() = %q", got)
	}
}
