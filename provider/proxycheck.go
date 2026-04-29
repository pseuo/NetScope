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
	"time"
)

type ProxyCheckProvider struct {
	APIKey string
	Client *http.Client
}

type ProxyCheckResult struct {
	IP           string
	Proxy        bool
	VPN          bool
	Tor          bool
	Hosting      bool
	Datacenter   bool
	Provider     string
	Organisation string
	ASN          string
	Country      string
	City         string
	RiskScore    int
	Type         string
	Status       string
	Message      string
	Raw          map[string]interface{}
}

func NewProxyCheckProvider(apiKey string) *ProxyCheckProvider {
	return NewProxyCheckProviderWithTimeout(apiKey, 8*time.Second)
}

func NewProxyCheckProviderWithTimeout(apiKey string, timeout time.Duration) *ProxyCheckProvider {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	return &ProxyCheckProvider{
		APIKey: apiKey,
		Client: &http.Client{Timeout: timeout},
	}
}

func (p *ProxyCheckProvider) Query(ip string) (*ProxyCheckResult, error) {
	if p.APIKey == "" {
		return nil, nil
	}

	u := fmt.Sprintf(
		"https://proxycheck.io/v3/%s?key=%s&days=7&ver=20-November-2025",
		url.PathEscape(ip),
		url.QueryEscape(p.APIKey),
	)

	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}

	resp, err := p.Client.Do(req)
	if err != nil {
		log.Printf("proxycheck request failed: ip=%s err=%v", ip, err)
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("proxycheck read body failed: ip=%s err=%v", ip, err)
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("proxycheck bad status: ip=%s status=%d body=%s", ip, resp.StatusCode, truncateForLog(body))
		return nil, fmt.Errorf("proxycheck status %d", resp.StatusCode)
	}

	var raw map[string]interface{}
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&raw); err != nil {
		log.Printf("proxycheck decode failed: ip=%s err=%v body=%s", ip, err, truncateForLog(body))
		return nil, err
	}

	result := &ProxyCheckResult{
		IP:     ip,
		Status: getStringAny(raw, "status"),
		Raw:    raw,
	}

	if msg := getStringAny(raw, "message"); msg != "" {
		result.Message = msg
	}

	// proxycheck 的核心数据通常按 IP 为 key
	if ipNode, ok := raw[ip].(map[string]interface{}); ok {
		parseProxyCheckIPNode(ipNode, result)
		log.Printf("proxycheck result: ip=%s provider=%q type=%q country=%q city=%q proxy=%t vpn=%t hosting=%t risk=%d",
			ip, result.Provider, result.Type, result.Country, result.City, result.Proxy, result.VPN, result.Hosting, result.RiskScore)
		return result, nil
	}

	// 兼容某些可能直接平铺的返回
	parseProxyCheckIPNode(raw, result)
	log.Printf("proxycheck fallback result: ip=%s provider=%q type=%q country=%q city=%q proxy=%t vpn=%t hosting=%t risk=%d",
		ip, result.Provider, result.Type, result.Country, result.City, result.Proxy, result.VPN, result.Hosting, result.RiskScore)
	return result, nil
}

func parseProxyCheckIPNode(node map[string]interface{}, result *ProxyCheckResult) {
	lookup := func(key string) string {
		if v := getStringAny(node, key); v != "" {
			return v
		}
		if network, ok := node["network"].(map[string]interface{}); ok {
			return getStringAny(network, key)
		}
		if location, ok := node["location"].(map[string]interface{}); ok {
			return getStringAny(location, key)
		}
		if detections, ok := node["detections"].(map[string]interface{}); ok {
			return getStringAny(detections, key)
		}
		return ""
	}

	lookupBool := func(key string) bool {
		if getBoolAny(node, key) || strBool(getStringAny(node, key)) {
			return true
		}
		if network, ok := node["network"].(map[string]interface{}); ok {
			if getBoolAny(network, key) || strBool(getStringAny(network, key)) {
				return true
			}
		}
		if detections, ok := node["detections"].(map[string]interface{}); ok {
			if getBoolAny(detections, key) || strBool(getStringAny(detections, key)) {
				return true
			}
		}
		return false
	}

	lookupInt := func(key string) int {
		if v := getIntAny(node, key); v != 0 {
			return v
		}
		if detections, ok := node["detections"].(map[string]interface{}); ok {
			return getIntAny(detections, key)
		}
		return 0
	}

	result.Provider = lookup("provider")
	if result.Provider == "" {
		result.Provider = lookup("organisation")
	}
	result.Organisation = lookup("organisation")

	asn := lookup("asn")
	if asn != "" {
		if asn[0] >= '0' && asn[0] <= '9' {
			result.ASN = "AS" + asn
		} else {
			result.ASN = asn
		}
	}

	result.Country = lookup("country")
	if result.Country == "" {
		result.Country = lookup("country_name")
	}
	result.City = lookup("city")
	if result.City == "" {
		result.City = lookup("city_name")
	}
	result.Type = lookup("type")

	result.RiskScore = lookupInt("risk")

	// 常见 proxy 标记
	result.Proxy = lookupBool("proxy")

	// 常见 vpn / type 判断
	result.VPN = lookupBool("vpn")
	if !result.VPN && containsType(result.Type, "vpn") {
		result.VPN = true
	}

	// Tor
	result.Tor = lookupBool("tor")
	if !result.Tor && containsType(result.Type, "tor") {
		result.Tor = true
	}

	// Hosting / Datacenter
	result.Hosting = lookupBool("hosting")
	result.Datacenter = lookupBool("datacenter")

	if !result.Hosting && containsType(result.Type, "hosting") {
		result.Hosting = true
	}
	if !result.Datacenter && (containsType(result.Type, "dc") || containsType(result.Type, "datacenter")) {
		result.Datacenter = true
	}

	// 如果已经识别为 proxy 且类型是 hosting/datacenter，也补上 hosting
	if result.Proxy && (result.Datacenter || containsType(result.Type, "hosting")) {
		result.Hosting = true
	}
}

func getIntAny(m map[string]interface{}, key string) int {
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}
	switch x := v.(type) {
	case float64:
		return int(x)
	case float32:
		return int(x)
	case int:
		return x
	case int64:
		return int(x)
	case string:
		n, _ := strconv.Atoi(x)
		return n
	default:
		return 0
	}
}

func getBoolAny(m map[string]interface{}, key string) bool {
	v, ok := m[key]
	if !ok || v == nil {
		return false
	}
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strBool(x)
	default:
		return false
	}
}

func strBool(s string) bool {
	switch s {
	case "yes", "true", "1", "True", "TRUE", "YES":
		return true
	default:
		return false
	}
}

func containsType(s, sub string) bool {
	if s == "" || sub == "" {
		return false
	}
	return containsIgnoreCase(s, sub)
}

func containsIgnoreCase(a, b string) bool {
	return len(a) >= len(b) && indexIgnoreCase(a, b) >= 0
}

func indexIgnoreCase(a, b string) int {
	la := len(a)
	lb := len(b)
	if lb == 0 {
		return 0
	}
	for i := 0; i+lb <= la; i++ {
		if equalFoldASCII(a[i:i+lb], b) {
			return i
		}
	}
	return -1
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		c1 := a[i]
		c2 := b[i]
		if c1 >= 'A' && c1 <= 'Z' {
			c1 = c1 + 32
		}
		if c2 >= 'A' && c2 <= 'Z' {
			c2 = c2 + 32
		}
		if c1 != c2 {
			return false
		}
	}
	return true
}
