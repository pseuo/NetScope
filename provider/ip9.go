package provider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type IP9Provider struct {
	Token  string
	Client *http.Client
}

type IP9Result struct {
	IP            string
	Country       string
	CountryCode   string
	Province      string
	City          string
	CityCode      string
	CityShortCode string
	Area          string
	PostCode      string
	AreaCode      string
	ISP           string
	Longitude     float64
	Latitude      float64
	LongIP        uint64
	BigArea       string
	IPType        string
}

type ip9Response struct {
	Ret  int     `json:"ret"`
	Data ip9Data `json:"data"`
	QT   float64 `json:"qt"`
}

type ip9Data struct {
	IP            string `json:"ip"`
	Country       string `json:"country"`
	CountryCode   string `json:"country_code"`
	Province      string `json:"prov"`
	City          string `json:"city"`
	CityCode      string `json:"city_code"`
	CityShortCode string `json:"city_short_code"`
	Area          string `json:"area"`
	PostCode      string `json:"post_code"`
	AreaCode      string `json:"area_code"`
	ISP           string `json:"isp"`
	Longitude     string `json:"lng"`
	Latitude      string `json:"lat"`
	LongIP        uint64 `json:"long_ip"`
	BigArea       string `json:"big_area"`
	IPType        string `json:"ip_type"`
}

func NewIP9Provider(token string) *IP9Provider {
	return NewIP9ProviderWithTimeout(token, 8*time.Second)
}

func NewIP9ProviderWithTimeout(token string, timeout time.Duration) *IP9Provider {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	return &IP9Provider{
		Token:  token,
		Client: &http.Client{Timeout: timeout},
	}
}

func (p *IP9Provider) Query(ip string) (*IP9Result, error) {
	if p.Token == "" {
		return nil, nil
	}

	u := fmt.Sprintf(
		"https://vip-40d99c47.ip9.com.cn/get?token=%s&ip=%s",
		url.QueryEscape(p.Token),
		url.QueryEscape(ip),
	)

	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}

	resp, err := p.Client.Do(req)
	if err != nil {
		log.Printf("ip9 request failed: ip=%s err=%v", ip, err)
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("ip9 read body failed: ip=%s err=%v", ip, err)
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("ip9 bad status: ip=%s status=%d body=%s", ip, resp.StatusCode, truncateForLog(body))
		return nil, fmt.Errorf("ip9 status %d", resp.StatusCode)
	}

	var raw ip9Response
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&raw); err != nil {
		log.Printf("ip9 decode failed: ip=%s err=%v body=%s", ip, err, truncateForLog(body))
		return nil, err
	}

	if raw.Ret != http.StatusOK {
		log.Printf("ip9 bad ret: ip=%s ret=%d body=%s", ip, raw.Ret, truncateForLog(body))
		return nil, fmt.Errorf("ip9 ret %d", raw.Ret)
	}

	result := &IP9Result{
		IP:            raw.Data.IP,
		Country:       raw.Data.Country,
		CountryCode:   raw.Data.CountryCode,
		Province:      raw.Data.Province,
		City:          raw.Data.City,
		CityCode:      raw.Data.CityCode,
		CityShortCode: raw.Data.CityShortCode,
		Area:          raw.Data.Area,
		PostCode:      raw.Data.PostCode,
		AreaCode:      raw.Data.AreaCode,
		ISP:           raw.Data.ISP,
		Longitude:     parseFloatString(raw.Data.Longitude),
		Latitude:      parseFloatString(raw.Data.Latitude),
		LongIP:        raw.Data.LongIP,
		BigArea:       raw.Data.BigArea,
		IPType:        raw.Data.IPType,
	}

	log.Printf("ip9 result: ip=%s country=%q province=%q city=%q isp=%q", ip, result.Country, result.Province, result.City, result.ISP)

	return result, nil
}

func parseFloatString(v string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(v), 64)
	return f
}
