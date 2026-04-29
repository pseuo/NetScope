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

type IPDataProvider struct {
	APIKey string
	Client *http.Client
}

type IPDataResult struct {
	IP            string         `json:"ip"`
	City          string         `json:"city"`
	Region        string         `json:"region"`
	RegionCode    string         `json:"region_code"`
	Country       string         `json:"country_name"`
	CountryCode   string         `json:"country_code"`
	Continent     string         `json:"continent_name"`
	ContinentCode string         `json:"continent_code"`
	PostalCode    string         `json:"postal"`
	Latitude      float64        `json:"latitude"`
	Longitude     float64        `json:"longitude"`
	ASN           IPDataASN      `json:"asn"`
	Timezone      IPDataTimezone `json:"time_zone"`
	Threat        IPDataThreat   `json:"threat"`
	Carrier       IPDataCarrier  `json:"carrier"`
}

type IPDataASN struct {
	ASN    string `json:"asn"`
	Name   string `json:"name"`
	Domain string `json:"domain"`
	Route  string `json:"route"`
	Type   string `json:"type"`
}

type IPDataTimezone struct {
	Name string `json:"name"`
}

type IPDataThreat struct {
	IsTor           bool `json:"is_tor"`
	IsProxy         bool `json:"is_proxy"`
	IsAnonymous     bool `json:"is_anonymous"`
	IsKnownAttacker bool `json:"is_known_attacker"`
	IsKnownAbuser   bool `json:"is_known_abuser"`
	IsThreat        bool `json:"is_threat"`
	IsBogon         bool `json:"is_bogon"`
}

type IPDataCarrier struct {
	Name string `json:"name"`
}

func NewIPDataProvider(apiKey string) *IPDataProvider {
	return NewIPDataProviderWithTimeout(apiKey, 8*time.Second)
}

func NewIPDataProviderWithTimeout(apiKey string, timeout time.Duration) *IPDataProvider {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	return &IPDataProvider{
		APIKey: strings.TrimSpace(apiKey),
		Client: &http.Client{Timeout: timeout},
	}
}

func (p *IPDataProvider) Query(ip string) (*IPDataResult, error) {
	if p.APIKey == "" {
		return nil, nil
	}

	u := fmt.Sprintf("https://api.ipdata.co/%s?api-key=%s", url.PathEscape(ip), url.QueryEscape(p.APIKey))
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}

	resp, err := p.Client.Do(req)
	if err != nil {
		log.Printf("ipdata request failed: ip=%s err=%v", ip, err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("ipdata bad status: ip=%s status=%d", ip, resp.StatusCode)
		return nil, fmt.Errorf("ipdata status %d", resp.StatusCode)
	}

	var result IPDataResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("ipdata decode failed: ip=%s err=%v", ip, err)
		return nil, err
	}

	log.Printf("ipdata result: ip=%s country=%q region=%q city=%q asn=%q", ip, result.Country, result.Region, result.City, result.ASN.ASN)
	return &result, nil
}

func (r *IPDataResult) NormalizedASN() string {
	asn := strings.TrimSpace(strings.ToUpper(r.ASN.ASN))
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
