package provider

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type IPInfoProvider struct {
	APIKey string
	Client *http.Client
}

type IPInfoResult struct {
	IP          string `json:"ip"`
	Hostname    string `json:"hostname"`
	City        string `json:"city"`
	Region      string `json:"region"`
	CountryCode string `json:"country"`
	Location    string `json:"loc"`
	Org         string `json:"org"`
	PostalCode  string `json:"postal"`
	Timezone    string `json:"timezone"`
	Anycast     bool   `json:"anycast"`
	Bogon       bool   `json:"bogon"`

	Latitude        float64
	Longitude       float64
	ASN             string
	ASNNumber       uint
	ASNOrganization string
}

func NewIPInfoProvider(apiKey string) *IPInfoProvider {
	return NewIPInfoProviderWithTimeout(apiKey, 8*time.Second)
}

func NewIPInfoProviderWithTimeout(apiKey string, timeout time.Duration) *IPInfoProvider {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	return &IPInfoProvider{
		APIKey: strings.TrimSpace(apiKey),
		Client: &http.Client{Timeout: timeout},
	}
}

func (p *IPInfoProvider) Query(ip string) (*IPInfoResult, error) {
	if p.APIKey == "" {
		return nil, nil
	}

	u := fmt.Sprintf("https://ipinfo.io/%s/json?token=%s", url.PathEscape(ip), url.QueryEscape(p.APIKey))
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}

	resp, err := p.Client.Do(req)
	if err != nil {
		log.Printf("ipinfo request failed: ip=%s err=%v", ip, err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("ipinfo bad status: ip=%s status=%d", ip, resp.StatusCode)
		return nil, fmt.Errorf("ipinfo status %d", resp.StatusCode)
	}

	var result IPInfoResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("ipinfo decode failed: ip=%s err=%v", ip, err)
		return nil, err
	}

	parseIPInfoLocation(&result)
	parseIPInfoOrg(&result)
	log.Printf("ipinfo result: ip=%s country=%q region=%q city=%q org=%q", ip, result.CountryCode, result.Region, result.City, result.Org)

	return &result, nil
}

func parseIPInfoLocation(result *IPInfoResult) {
	parts := strings.Split(result.Location, ",")
	if len(parts) != 2 {
		return
	}
	lat, _ := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
	lon, _ := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
	result.Latitude = lat
	result.Longitude = lon
}

func parseIPInfoOrg(result *IPInfoResult) {
	org := strings.TrimSpace(result.Org)
	if org == "" {
		return
	}
	fields := strings.Fields(org)
	if len(fields) == 0 {
		return
	}

	asn := normalizeIPInfoASN(fields[0])
	if asn == "" {
		result.ASNOrganization = org
		return
	}
	result.ASN = asn
	result.ASNNumber = parseIPInfoASNNumber(asn)
	result.ASNOrganization = strings.TrimSpace(strings.TrimPrefix(org, fields[0]))
	if result.ASNOrganization == "" {
		result.ASNOrganization = org
	}
}

func normalizeIPInfoASN(asn string) string {
	asn = strings.TrimSpace(strings.ToUpper(asn))
	if asn == "" {
		return ""
	}
	if strings.HasPrefix(asn, "AS") {
		return asn
	}
	if _, err := strconv.ParseUint(asn, 10, 64); err == nil {
		return "AS" + asn
	}
	return ""
}

func parseIPInfoASNNumber(asn string) uint {
	asn = strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(asn)), "AS")
	n, _ := strconv.ParseUint(asn, 10, 64)
	return uint(n)
}
