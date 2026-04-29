package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	MaxMindCityDB     string
	MaxMindCountryDB  string
	MaxMindASNDB      string
	DBIPCityDB        string
	DBIPCountryDB     string
	DBIPASNDB         string
	IP2LocationAPIKey string
	IPInfoAPIKey      string
	IPAPIBaseURL      string
	IPDataAPIKey      string
	IPDataCloudAPIKey string
	IPingBaseURL      string
	IP9Token          string
	ProxyCheckAPIKey  string
	IPv4CheckURL      string
	IPv6CheckURL      string
	IPv6CheckURLs     []string
	ProviderTimeout   time.Duration
	ProxyCheckTimeout time.Duration
	AggregatorTimeout time.Duration
	DNSTimeout        time.Duration
	ReverseDNSTimeout time.Duration
	NATICEServers     []NATICEServerConfig
}

type NATICEServerConfig struct {
	URLs       []string
	Username   string
	Credential string
}

func getEnv(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

func latestFile(pattern, fallback string) string {
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return fallback
	}
	return filepath.ToSlash(matches[len(matches)-1])
}

func getEnvDurationMS(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	ms, err := strconv.Atoi(v)
	if err != nil || ms <= 0 {
		return def
	}
	return time.Duration(ms) * time.Millisecond
}

func parseCSVEnv(key string, defaults []string) []string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return defaults
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	if len(out) == 0 {
		return defaults
	}
	return out
}

func New() *Config {
	iceServers := []NATICEServerConfig{
		{
			URLs: parseCSVEnv("NAT_STUN_URLS", []string{
				"stun:stun.l.google.com:19302",
				"stun:stun1.l.google.com:19302",
				"stun:stun2.l.google.com:19302",
				"stun:stun3.l.google.com:19302",
				"stun:stun4.l.google.com:19302",
				"stun:global.stun.twilio.com:3478",
				"stun:stun.miwifi.com:3478",
				"stun:stun.chat.bilibili.com:3478",
				"stun:turn.cloudflare.com:3478",
				"stun:stun.nextcloud.com:3478",
			}),
		},
	}

	turnURLs := parseCSVEnv("NAT_TURN_URLS", nil)
	turnUsername := strings.TrimSpace(getEnv("NAT_TURN_USERNAME", ""))
	turnCredential := strings.TrimSpace(getEnv("NAT_TURN_CREDENTIAL", ""))
	if len(turnURLs) > 0 && turnUsername != "" && turnCredential != "" {
		iceServers = append(iceServers, NATICEServerConfig{
			URLs:       turnURLs,
			Username:   turnUsername,
			Credential: turnCredential,
		})
	}

	ipv6CheckURL := getEnv("IPV6_CHECK_URL", "")
	ipv6CheckURLs := parseCSVEnv("IPV6_CHECK_URLS", nil)
	if len(ipv6CheckURLs) == 0 && ipv6CheckURL != "" {
		ipv6CheckURLs = []string{ipv6CheckURL}
	}
	if ipv6CheckURL == "" && len(ipv6CheckURLs) > 0 {
		ipv6CheckURL = ipv6CheckURLs[0]
	}

	return &Config{
		MaxMindCityDB:     getEnv("MAXMIND_CITY_DB", "./data/GeoLite2-City.mmdb"),
		MaxMindCountryDB:  getEnv("MAXMIND_COUNTRY_DB", "./data/GeoLite2-Country.mmdb"),
		MaxMindASNDB:      getEnv("MAXMIND_ASN_DB", "./data/GeoLite2-ASN.mmdb"),
		DBIPCityDB:        getEnv("DBIP_CITY_DB", latestFile("data/dbip-city-lite-*.mmdb", "./data/dbip-city-lite.mmdb")),
		DBIPCountryDB:     getEnv("DBIP_COUNTRY_DB", latestFile("data/dbip-country-lite-*.mmdb", "./data/dbip-country-lite.mmdb")),
		DBIPASNDB:         getEnv("DBIP_ASN_DB", latestFile("data/dbip-asn-lite-*.mmdb", "./data/dbip-asn-lite.mmdb")),
		IP2LocationAPIKey: getEnv("IP2LOCATION_API_KEY", ""),
		IPInfoAPIKey:      getEnv("IPINFO_API_KEY", ""),
		IPAPIBaseURL:      getEnv("IPAPI_BASE_URL", "http://ip-api.com/json"),
		IPDataAPIKey:      getEnv("IPDATA_API_KEY", ""),
		IPDataCloudAPIKey: getEnv("IPDATACLOUD_API_KEY", ""),
		IPingBaseURL:      getEnv("IPING_BASE_URL", "https://api.iping.cc/v1/query"),
		IP9Token:          getEnv("IP9_TOKEN", ""),
		ProxyCheckAPIKey:  getEnv("PROXYCHECK_API_KEY", ""),
		IPv4CheckURL:      getEnv("IPV4_CHECK_URL", ""),
		IPv6CheckURL:      ipv6CheckURL,
		IPv6CheckURLs:     ipv6CheckURLs,
		ProviderTimeout:   getEnvDurationMS("PROVIDER_TIMEOUT_MS", 2500*time.Millisecond),
		ProxyCheckTimeout: getEnvDurationMS("PROXYCHECK_TIMEOUT_MS", 5000*time.Millisecond),
		AggregatorTimeout: getEnvDurationMS("AGGREGATOR_TIMEOUT_MS", 3000*time.Millisecond),
		DNSTimeout:        getEnvDurationMS("DNS_TIMEOUT_MS", 1500*time.Millisecond),
		ReverseDNSTimeout: getEnvDurationMS("REVERSE_DNS_TIMEOUT_MS", 1200*time.Millisecond),
		NATICEServers:     iceServers,
	}
}
