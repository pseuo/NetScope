package provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type IPAPIProvider struct {
	BaseURL string
	Client  *http.Client
}

type IPAPIResult struct {
	Query       string  `json:"query"`
	Status      string  `json:"status"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	RegionName  string  `json:"regionName"`
	City        string  `json:"city"`
	Zip         string  `json:"zip"`
	Timezone    string  `json:"timezone"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
	Reverse     string  `json:"reverse"`
	Mobile      bool    `json:"mobile"`
	Proxy       bool    `json:"proxy"`
	Hosting     bool    `json:"hosting"`
}

func NewIPAPIProvider(baseURL string) *IPAPIProvider {
	return NewIPAPIProviderWithTimeout(baseURL, 8*time.Second)
}

func NewIPAPIProviderWithTimeout(baseURL string, timeout time.Duration) *IPAPIProvider {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	return &IPAPIProvider{
		BaseURL: baseURL,
		Client:  &http.Client{Timeout: timeout},
	}
}

func (p *IPAPIProvider) Query(ip string) (*IPAPIResult, error) {
	fields := "status,country,countryCode,regionName,city,zip,timezone,lat,lon,isp,org,as,reverse,mobile,proxy,hosting,query"
	u := fmt.Sprintf("%s/%s?fields=%s",
		p.BaseURL,
		url.QueryEscape(ip),
		url.QueryEscape(fields),
	)

	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}

	resp, err := p.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result IPAPIResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}
