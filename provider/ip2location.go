package provider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"
)

type IP2LocationProvider struct {
	APIKey string
	Client *http.Client
}

type IP2LocationResult struct {
	IP              string
	Country         string
	CountryCode     string
	Region          string
	City            string
	Latitude        float64
	Longitude       float64
	ZipCode         string
	TimeZone        string
	ISP             string
	Organization    string
	ASN             string
	AS              string
	ASUsageType     string
	UsageType       string
	Proxy           bool
	VPN             bool
	Tor             bool
	Datacenter      bool
	Hostname        string
}

func NewIP2LocationProvider(apiKey string) *IP2LocationProvider {
	return NewIP2LocationProviderWithTimeout(apiKey, 8*time.Second)
}

func NewIP2LocationProviderWithTimeout(apiKey string, timeout time.Duration) *IP2LocationProvider {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	return &IP2LocationProvider{
		APIKey: apiKey,
		Client: &http.Client{Timeout: timeout},
	}
}

func (p *IP2LocationProvider) Query(ip string) (*IP2LocationResult, error) {
	if p.APIKey == "" {
		return nil, nil
	}

	u := fmt.Sprintf("https://api.ip2location.io/?key=%s&ip=%s&format=json",
		url.QueryEscape(p.APIKey),
		url.QueryEscape(ip),
	)

	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}

	resp, err := p.Client.Do(req)
	if err != nil {
		log.Printf("ip2location request failed: ip=%s err=%v", ip, err)
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("ip2location read body failed: ip=%s err=%v", ip, err)
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("ip2location bad status: ip=%s status=%d body=%s", ip, resp.StatusCode, truncateForLog(body))
		return nil, fmt.Errorf("ip2location status %d", resp.StatusCode)
	}

	var raw map[string]interface{}
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&raw); err != nil {
		log.Printf("ip2location decode failed: ip=%s err=%v body=%s", ip, err, truncateForLog(body))
		return nil, err
	}

	result := &IP2LocationResult{
		IP:           getString(raw, "ip"),
		Country:      getString(raw, "country_name"),
		CountryCode:  getString(raw, "country_code"),
		Region:       getString(raw, "region_name"),
		City:         getString(raw, "city_name"),
		Latitude:     getFloat(raw, "latitude"),
		Longitude:    getFloat(raw, "longitude"),
		ZipCode:      getString(raw, "zip_code"),
		TimeZone:     getString(raw, "time_zone"),
		ISP:          getString(raw, "isp"),
		Organization: getString(raw, "organization"),
		ASN:          getString(raw, "asn"),
		AS:           getString(raw, "as"),
		UsageType:    getString(raw, "usage_type"),
		Hostname:     getString(raw, "domain"),
	}

	if asInfo, ok := raw["as_info"].(map[string]interface{}); ok {
		result.ASUsageType = getString(asInfo, "as_usage_type")
		if result.ASN == "" {
			result.ASN = getString(asInfo, "asn")
		}
		if result.AS == "" {
			result.AS = getString(asInfo, "as_name")
		}
	}

	if sec, ok := raw["security"].(map[string]interface{}); ok {
		result.Proxy = getBool(sec, "is_proxy")
		result.VPN = getBool(sec, "is_vpn")
		result.Tor = getBool(sec, "is_tor")
		result.Datacenter = getBool(sec, "is_data_center")
	}

	if !result.Proxy {
		result.Proxy = getBool(raw, "is_proxy")
	}
	if !result.VPN {
		result.VPN = getBool(raw, "is_vpn")
	}
	if !result.Tor {
		result.Tor = getBool(raw, "is_tor")
	}
	if !result.Datacenter {
		result.Datacenter = getBool(raw, "is_data_center")
	}

	log.Printf("ip2location result: ip=%s isp=%q org=%q asn=%q usage_type=%q as_usage_type=%q proxy=%t vpn=%t tor=%t datacenter=%t",
		ip,
		result.ISP,
		result.Organization,
		result.ASN,
		result.UsageType,
		result.ASUsageType,
		result.Proxy,
		result.VPN,
		result.Tor,
		result.Datacenter,
	)

	return result, nil
}

func getString(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func getFloat(m map[string]interface{}, key string) float64 {
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return n
	case float32:
		return float64(n)
	default:
		return 0
	}
}

func getBool(m map[string]interface{}, key string) bool {
	v, ok := m[key]
	if !ok || v == nil {
		return false
	}
	b, ok := v.(bool)
	return ok && b
}
