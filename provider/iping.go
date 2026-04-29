package provider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type IPingProvider struct {
	BaseURL string
	Client  *http.Client
}

type IPingResult struct {
	IP             string
	Continent      string
	Country        string
	Region         string
	City           string
	Longitude      float64
	Latitude       float64
	ISP            string
	IsProxy        bool
	Type           string
	UsageType      string
	RiskScore      int
	RiskTag        string
	ASN            string
	ASNOwner       string
	ASNType        string
	ASNDomain      string
	ASNCountry     string
	Company        string
	CompanyDomain  string
	CompanyType    string
	CompanyCountry string
}

func NewIPingProvider(baseURL string) *IPingProvider {
	return NewIPingProviderWithTimeout(baseURL, 8*time.Second)
}

func NewIPingProviderWithTimeout(baseURL string, timeout time.Duration) *IPingProvider {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	return &IPingProvider{
		BaseURL: strings.TrimRight(baseURL, "?&"),
		Client:  &http.Client{Timeout: timeout},
	}
}

func (p *IPingProvider) Query(ip string) (*IPingResult, error) {
	if p.BaseURL == "" {
		return nil, nil
	}
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil || parsedIP.To4() == nil {
		return nil, nil
	}

	u, err := url.Parse(p.BaseURL)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("ip", ip)
	if q.Get("language") == "" {
		q.Set("language", "zh")
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := p.Client.Do(req)
	if err != nil {
		log.Printf("iping request failed: ip=%s err=%v", ip, err)
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("iping read body failed: ip=%s err=%v", ip, err)
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("iping bad status: ip=%s status=%d body=%s", ip, resp.StatusCode, truncateForLog(body))
		return nil, fmt.Errorf("iping status %d", resp.StatusCode)
	}

	var raw struct {
		Code int                    `json:"code"`
		Msg  string                 `json:"msg"`
		Data map[string]interface{} `json:"data"`
	}
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&raw); err != nil {
		log.Printf("iping decode failed: ip=%s err=%v body=%s", ip, err, truncateForLog(body))
		return nil, err
	}

	if raw.Code != http.StatusOK {
		log.Printf("iping bad code: ip=%s code=%d msg=%q body=%s", ip, raw.Code, raw.Msg, truncateForLog(body))
		return nil, fmt.Errorf("iping code %d", raw.Code)
	}
	if raw.Data == nil {
		return nil, fmt.Errorf("iping empty data")
	}

	result := &IPingResult{
		IP:             getStringAny(raw.Data, "ip"),
		Continent:      getStringAny(raw.Data, "continent"),
		Country:        getStringAny(raw.Data, "country"),
		Region:         getStringAny(raw.Data, "region"),
		City:           getStringAny(raw.Data, "city"),
		Longitude:      getFloatAny(raw.Data, "longitude"),
		Latitude:       getFloatAny(raw.Data, "latitude"),
		ISP:            getStringAny(raw.Data, "isp"),
		IsProxy:        strBool(getStringAny(raw.Data, "is_proxy")),
		Type:           getStringAny(raw.Data, "type"),
		UsageType:      getStringAny(raw.Data, "usage_type"),
		RiskScore:      getIntAny(raw.Data, "risk_score"),
		RiskTag:        getStringAny(raw.Data, "risk_tag"),
		ASN:            getStringAny(raw.Data, "asn"),
		ASNOwner:       getStringAny(raw.Data, "as_owner"),
		ASNType:        getStringAny(raw.Data, "as_type"),
		ASNDomain:      getStringAny(raw.Data, "as_domain"),
		ASNCountry:     getStringAny(raw.Data, "as_country"),
		Company:        getStringAny(raw.Data, "company"),
		CompanyDomain:  getStringAny(raw.Data, "company_domain"),
		CompanyType:    getStringAny(raw.Data, "company_type"),
		CompanyCountry: getStringAny(raw.Data, "company_country"),
	}

	log.Printf("iping result: ip=%s country=%q region=%q city=%q isp=%q asn=%q", ip, result.Country, result.Region, result.City, result.ISP, result.ASN)

	return result, nil
}
