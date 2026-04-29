package provider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"
)

var (
	jsonSecretFieldRe = regexp.MustCompile(`(?i)("(?:api[_-]?key|key|token|access[_-]?token|authorization|credential)"\s*:\s*")([^"]*)(")`)
	querySecretRe     = regexp.MustCompile(`(?i)\b((?:api[_-]?key|key|token|access[_-]?token|credential)=)([^&\s"']+)`)
)

type IPDataCloudProvider struct {
	APIKey string
	Client *http.Client
}

type IPDataCloudResult struct {
	Continent      string
	Country        string
	CountryCode    string
	Province       string
	City           string
	District       string
	Street         string
	Radius         string
	Longitude      float64
	Latitude       float64
	AreaCode       string
	ISP            string
	TimeZone       string
	Elevation      string
	WeatherStation string
	ZipCode        string
	CityCode       string
}

func NewIPDataCloudProvider(apiKey string) *IPDataCloudProvider {
	return NewIPDataCloudProviderWithTimeout(apiKey, 8*time.Second)
}

func NewIPDataCloudProviderWithTimeout(apiKey string, timeout time.Duration) *IPDataCloudProvider {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	return &IPDataCloudProvider{
		APIKey: apiKey,
		Client: &http.Client{Timeout: timeout},
	}
}

func (p *IPDataCloudProvider) Query(ip string) (*IPDataCloudResult, error) {
	if p.APIKey == "" {
		return nil, nil
	}

	u := fmt.Sprintf(
		"https://api.ipdatacloud.com/v2/query?ip=%s&key=%s",
		url.QueryEscape(ip),
		url.QueryEscape(p.APIKey),
	)

	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}

	resp, err := p.Client.Do(req)
	if err != nil {
		log.Printf("ipdatacloud request failed: ip=%s err=%v", ip, err)
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("ipdatacloud read body failed: ip=%s err=%v", ip, err)
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("ipdatacloud bad status: ip=%s status=%d body=%s", ip, resp.StatusCode, truncateForLog(body))
		return nil, fmt.Errorf("ipdatacloud status %d", resp.StatusCode)
	}

	var raw map[string]interface{}
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&raw); err != nil {
		log.Printf("ipdatacloud decode failed: ip=%s err=%v body=%s", ip, err, truncateForLog(body))
		return nil, err
	}

	payload := raw
	if dataNode, ok := raw["data"].(map[string]interface{}); ok {
		if locationNode, ok := dataNode["location"].(map[string]interface{}); ok {
			payload = locationNode
		} else {
			payload = dataNode
		}
	}

	result := &IPDataCloudResult{
		Continent:      getStringAny(payload, "continent"),
		Country:        getStringAny(payload, "country"),
		CountryCode:    getStringAny(payload, "country_code"),
		Province:       getStringAny(payload, "province"),
		City:           getStringAny(payload, "city"),
		District:       getStringAny(payload, "district"),
		Street:         getStringAny(payload, "street"),
		Radius:         getStringAny(payload, "radius"),
		Longitude:      getFloatAny(payload, "longitude"),
		Latitude:       getFloatAny(payload, "latitude"),
		AreaCode:       getStringAny(payload, "area_code"),
		ISP:            getStringAny(payload, "isp"),
		TimeZone:       getStringAny(payload, "time_zone"),
		Elevation:      getStringAny(payload, "elevation"),
		WeatherStation: getStringAny(payload, "weather_station"),
		ZipCode:        getStringAny(payload, "zip_code"),
		CityCode:       getStringAny(payload, "city_code"),
	}

	if result.Longitude == 0 {
		result.Longitude = getFloatAny(payload, "lng")
	}
	if result.Latitude == 0 {
		result.Latitude = getFloatAny(payload, "lat")
	}

	if result.Country == "" && result.Province == "" && result.City == "" && result.ISP == "" {
		log.Printf("ipdatacloud empty result body: ip=%s body=%s", ip, truncateForLog(body))
	}

	log.Printf("ipdatacloud result: ip=%s country=%q province=%q city=%q isp=%q", ip, result.Country, result.Province, result.City, result.ISP)

	return result, nil
}

func truncateForLog(body []byte) string {
	const max = 300
	s := redactSecretsForLog(string(body))
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func redactSecretsForLog(s string) string {
	s = jsonSecretFieldRe.ReplaceAllString(s, `${1}[REDACTED]${3}`)
	s = querySecretRe.ReplaceAllString(s, `${1}[REDACTED]`)
	return s
}

func getStringAny(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		if x {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", x)
	}
}

func getFloatAny(m map[string]interface{}, key string) float64 {
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}

	switch x := v.(type) {
	case float64:
		return x
	case float32:
		return float64(x)
	case string:
		f, _ := strconv.ParseFloat(x, 64)
		return f
	default:
		return 0
	}
}
