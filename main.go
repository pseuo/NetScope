package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	"ip-query/config"
	"ip-query/model"
	"ip-query/provider"
	"ip-query/service"
)

const (
	ipCacheCookieName       = "ipq_session"
	ipCacheTTL              = time.Hour
	ipCacheMaxEntries       = 4096
	ipCacheCleanupInterval  = 10 * time.Minute
	trustedProxiesEnv       = "TRUSTED_PROXIES"
	defaultIPCacheMaxAgeSec = int(ipCacheTTL / time.Second)
	ipCacheMaxBodyBytes     = 1024
)

type cachedIPResult struct {
	IP        string    `json:"ip"`
	IPVersion string    `json:"ip_version"`
	Version   int       `json:"version"`
	Available bool      `json:"available"`
	Source    string    `json:"source"`
	CachedAt  time.Time `json:"cached_at"`
}

type ipCacheEntry struct {
	IPv4 cachedIPResult
	IPv6 cachedIPResult
	UpdatedAt time.Time
}

type ipCacheStore struct {
	mu         sync.RWMutex
	entries    map[string]ipCacheEntry
	maxEntries int
}

func newIPCacheStore() *ipCacheStore {
	return &ipCacheStore{entries: make(map[string]ipCacheEntry), maxEntries: ipCacheMaxEntries}
}

func main() {
	loadDotEnv()

	cfg := config.New()
	fmt.Printf("config loaded: dbip=%t ip2location=%t ipinfo=%t ipdata=%t ipdatacloud=%t iping=%t ip9=%t proxycheck=%t provider_timeout=%s proxycheck_timeout=%s aggregator_timeout=%s dns_timeout=%s reverse_dns_timeout=%s\n",
		cfg.DBIPCityDB != "" || cfg.DBIPCountryDB != "" || cfg.DBIPASNDB != "",
		cfg.IP2LocationAPIKey != "",
		cfg.IPInfoAPIKey != "",
		cfg.IPDataAPIKey != "",
		cfg.IPDataCloudAPIKey != "",
		cfg.IPingBaseURL != "",
		cfg.IP9Token != "",
		cfg.ProxyCheckAPIKey != "",
		cfg.ProviderTimeout,
		cfg.ProxyCheckTimeout,
		cfg.AggregatorTimeout,
		cfg.DNSTimeout,
		cfg.ReverseDNSTimeout,
	)

	maxmind, err := provider.NewMaxMindProvider(cfg.MaxMindCityDB, cfg.MaxMindCountryDB, cfg.MaxMindASNDB)
	if err != nil {
		log.Printf("maxmind provider disabled: %v", err)
	}
	if maxmind != nil {
		defer maxmind.Close()
	}
	dbip, err := provider.NewDBIPProvider(cfg.DBIPCityDB, cfg.DBIPCountryDB, cfg.DBIPASNDB)
	if err != nil {
		log.Printf("db-ip provider disabled: %v", err)
	}
	if dbip != nil {
		defer dbip.Close()
	}

	ip2 := provider.NewIP2LocationProviderWithTimeout(cfg.IP2LocationAPIKey, cfg.ProviderTimeout)
	ipinfo := provider.NewIPInfoProviderWithTimeout(cfg.IPInfoAPIKey, cfg.ProviderTimeout)
	ipapi := provider.NewIPAPIProviderWithTimeout(cfg.IPAPIBaseURL, cfg.ProviderTimeout)
	ipdata := provider.NewIPDataProviderWithTimeout(cfg.IPDataAPIKey, cfg.ProviderTimeout)
	ipdc := provider.NewIPDataCloudProviderWithTimeout(cfg.IPDataCloudAPIKey, cfg.ProviderTimeout)
	iping := provider.NewIPingProviderWithTimeout(cfg.IPingBaseURL, cfg.ProviderTimeout)
	ip9 := provider.NewIP9ProviderWithTimeout(cfg.IP9Token, cfg.ProviderTimeout)
	pcx := provider.NewProxyCheckProviderWithTimeout(cfg.ProxyCheckAPIKey, cfg.ProxyCheckTimeout)

	agg := service.NewAggregatorWithTimeouts(maxmind, dbip, ip2, ipinfo, ipapi, ipdata, ipdc, iping, ip9, pcx, cfg.AggregatorTimeout, cfg.DNSTimeout, cfg.ReverseDNSTimeout)
	ipCache := newIPCacheStore()
	stopIPCacheCleanup := ipCache.startCleanup(ipCacheCleanupInterval)
	defer stopIPCacheCleanup()

	r := gin.Default()
	if err := r.SetTrustedProxies(trustedProxiesFromEnv()); err != nil {
		log.Fatalf("invalid %s: %v", trustedProxiesEnv, err)
	}
	r.LoadHTMLGlob("templates/*")
	r.Static("/assets", "./assets")

	r.GET("/", func(c *gin.Context) {
		if wantsHTML(c) {
			c.HTML(200, "index.html", nil)
			return
		}
		allowIPCheckCORS(c)
		resp := dualIPResponse(c, ipCache)
		if wantsPlainIP(c) {
			c.String(http.StatusOK, "%s", dualIPPlainText(resp))
			return
		}
		c.JSON(http.StatusOK, resp)
	})

	r.GET("/more", func(c *gin.Context) {
		lang := c.DefaultQuery("lang", "zh")
		ip := clientIP(c)
		resp, err := agg.Query(ip, lang)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, resp)
	})

	r.GET("/img", func(c *gin.Context) {
		ip := clientIP(c)
		location := "NetScope"
		if resp, err := agg.Query(ip, "en"); err == nil {
			location = imageLocation(resp)
		}
		writeIPImage(c, ip, location)
	})

	r.GET("/ip-search", func(c *gin.Context) {
		c.HTML(200, "ip-search.html", nil)
	})

	r.GET("/ip-look", func(c *gin.Context) {
		c.HTML(200, "ip-look.html", nil)
	})

	r.GET("/nat-test", func(c *gin.Context) {
		c.HTML(200, "nat-test.html", nil)
	})

	r.GET("/nat-test.php", func(c *gin.Context) {
		c.HTML(200, "nat-test.html", nil)
	})

	r.GET("/ipv6-test", func(c *gin.Context) {
		c.HTML(200, "ipv6-test.html", nil)
	})

	r.GET("/ipv6-test.php", func(c *gin.Context) {
		c.HTML(200, "ipv6-test.html", nil)
	})

	r.GET("/cdn-ipv6", func(c *gin.Context) {
		c.HTML(200, "cdn-ipv6.html", nil)
	})

	r.GET("/cdn-ipv6.php", func(c *gin.Context) {
		c.HTML(200, "cdn-ipv6.html", nil)
	})

	r.GET("/bandwidth-calculator", func(c *gin.Context) {
		c.HTML(200, "bandwidth-calculator.html", nil)
	})

	r.GET("/bandwidth-calculator.php", func(c *gin.Context) {
		c.HTML(200, "bandwidth-calculator.html", nil)
	})

	r.GET("/screen-test", func(c *gin.Context) {
		c.HTML(200, "screen-test.html", nil)
	})

	r.GET("/screen-test.php", func(c *gin.Context) {
		c.HTML(200, "screen-test.html", nil)
	})

	toolPages := map[string]bool{
		"ipv4-representations":    true,
		"ipv6-nat64":              true,
		"ipv4-range-to-cidr":      true,
		"cidr-aggregator":         true,
		"ipv4-cidr-to-netmask":    true,
		"ipv6-range-to-cidr":      true,
		"ipv4-wildcard-mask":      true,
		"ipv4-subnet-calculator":  true,
		"ipv6-subnet-calculator":  true,
		"network-ip-calculator":   true,
		"ipv6-expand-compress":    true,
		"address-count-by-prefix": true,
		"cidr-to-ip-range":        true,
		"netmask-to-cidr":         true,
		"ipv6-cidr-to-range":      true,
		"ip-address-type":         true,
		"ip-validator":            true,
		"reverse-dns-generator":   true,
		"subnet-splitter":         true,
		"bulk-ip-calculator":      true,
	}

	r.GET("/ip-tools", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/tools")
	})

	r.GET("/tools", func(c *gin.Context) {
		c.HTML(200, "ip-tools.html", gin.H{
		"Title":       "IP 工具大全 - NetScope 网络视镜",
			"Description": "在线 IPv4、IPv6、CIDR、子网掩码、地址范围、反向 DNS、NAT64 和批量 IP 计算工具。",
		})
	})

	r.GET("/tools/:slug", func(c *gin.Context) {
		slug := c.Param("slug")
		if !toolPages[slug] {
			c.Status(http.StatusNotFound)
			return
		}
		c.HTML(200, "ip-tools.html", toolPageMeta(slug))
	})

	r.GET("/api/device-info", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"ip":                 clientIP(c),
			"user_agent":         c.GetHeader("User-Agent"),
			"accept_language":    c.GetHeader("Accept-Language"),
			"sec_ch_ua":          c.GetHeader("Sec-CH-UA"),
			"sec_ch_ua_mobile":   c.GetHeader("Sec-CH-UA-Mobile"),
			"sec_ch_ua_platform": c.GetHeader("Sec-CH-UA-Platform"),
			"sec_ch_ua_arch":     c.GetHeader("Sec-CH-UA-Arch"),
			"sec_ch_ua_bitness":  c.GetHeader("Sec-CH-UA-Bitness"),
			"x_forwarded_for":    c.GetHeader("X-Forwarded-For"),
			"x_real_ip":          c.GetHeader("X-Real-IP"),
			"cf_connecting_ip":   c.GetHeader("CF-Connecting-IP"),
			"true_client_ip":     c.GetHeader("True-Client-IP"),
			"fastly_client_ip":   c.GetHeader("Fastly-Client-IP"),
			"forwarded":          c.GetHeader("Forwarded"),
			"remote_addr":        c.Request.RemoteAddr,
		})
	})

	r.GET("/api/ip", func(c *gin.Context) {
		query := c.Query("q")
		lang := c.DefaultQuery("lang", "zh")
		if query == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing q"})
			return
		}

		resp, err := agg.Query(query, lang)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, resp)
	})

	r.GET("/api/myip", func(c *gin.Context) {
		allowIPCheckCORS(c)
		ip := clientIP(c)
		version := service.DetectIPVersion(ip)
		ipv4 := any(false)
		ipv6 := any(false)
		if version == "IPv4" {
			ipv4 = ip
		}
		if version == "IPv6" {
			ipv6 = ip
		}
		c.JSON(200, gin.H{
			"ip":         ip,
			"ip_version": version,
			"ipv4":       ipv4,
			"ipv6":       ipv6,
			"is_ipv4":    version == "IPv4",
			"is_ipv6":    version == "IPv6",
		})
	})

	r.GET("/api/my-ipv4", func(c *gin.Context) {
		allowIPCheckCORS(c)
		ip := clientIPVersion(c, 4)
		parsed := net.ParseIP(ip)
		if parsed == nil || parsed.To4() == nil {
			c.JSON(200, gin.H{
				"ip":         "",
				"ip_version": "",
				"ipv4":       false,
				"ipv6":       false,
				"is_ipv4":    false,
				"is_ipv6":    false,
				"available":  false,
			})
			return
		}
		c.JSON(200, gin.H{
			"ip":         ip,
			"ip_version": "IPv4",
			"ipv4":       ip,
			"ipv6":       false,
			"version":    4,
			"is_ipv4":    true,
			"is_ipv6":    false,
			"available":  true,
		})
	})

	r.GET("/api/my-ipv6", func(c *gin.Context) {
		allowIPCheckCORS(c)
		ip := clientIPVersion(c, 6)
		parsed := net.ParseIP(ip)
		if parsed == nil || parsed.To4() != nil {
			sessionID := ensureIPCacheSession(c)
			cachedIPv4, cachedIPv6 := ipCache.get(sessionID)
			currentIPv4 := clientIPVersion(c, 4)
			if currentIPv4 != "" && cachedIPv4.Available && currentIPv4 != cachedIPv4.IP {
				cachedIPv6 = cachedIPResult{}
				ipCache.clearVersion(sessionID, 6)
			}
			if cachedIPv6.Available {
				c.JSON(200, cachedIPv6APIResponse(cachedIPv6))
				return
			}
			c.JSON(200, gin.H{
				"ip":         "",
				"ip_version": "",
				"ipv4":       false,
				"ipv6":       false,
				"is_ipv4":    false,
				"is_ipv6":    false,
				"available":  false,
			})
			return
		}
		ipCache.set(ensureIPCacheSession(c), cachedIPResult{
			IP:        ip,
			IPVersion: "IPv6",
			Version:   6,
			Available: true,
			Source:    "cache",
			CachedAt:  time.Now().UTC(),
		})
		c.JSON(200, gin.H{
			"ip":         ip,
			"ip_version": "IPv6",
			"ipv4":       false,
			"ipv6":       ip,
			"version":    6,
			"is_ipv4":    false,
			"is_ipv6":    true,
			"available":  true,
			"source":     "current_request",
		})
	})

	r.GET("/api/my-dual", func(c *gin.Context) {
		allowIPCheckCORS(c)
		resp := dualIPResponse(c, ipCache)
		if wantsPlainIP(c) {
			c.String(http.StatusOK, "%s", dualIPPlainText(resp))
			return
		}
		c.JSON(200, resp)
	})

	r.POST("/api/ip-cache", func(c *gin.Context) {
		allowIPCheckCORS(c, http.MethodPost)
		if c.Request.ContentLength > ipCacheMaxBodyBytes {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request body too large"})
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, ipCacheMaxBodyBytes)
		var req struct {
			IP        string `json:"ip"`
			IPVersion string `json:"ip_version"`
			Version   int    `json:"version"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			if strings.Contains(err.Error(), "request body too large") {
				c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request body too large"})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		version := req.Version
		if version == 0 && req.IPVersion == "IPv4" {
			version = 4
		}
		if version == 0 && req.IPVersion == "IPv6" {
			version = 6
		}
		if !ipMatchesVersion(req.IP, version) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid ip version"})
			return
		}

		sessionID := ensureIPCacheSession(c)
		result := cachedIPResult{
			IP:        req.IP,
			IPVersion: ipVersionLabel(version),
			Version:   version,
			Available: true,
			Source:    "cache",
			CachedAt:  time.Now().UTC(),
		}
		ipCache.set(sessionID, result)
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	r.OPTIONS("/api/ip-cache", func(c *gin.Context) {
		allowIPCheckCORS(c, http.MethodPost)
		c.Status(http.StatusNoContent)
	})

	r.GET("/api/ip-check-config", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"dual_url":  "/api/my-dual",
			"ipv4_url":  cfg.IPv4CheckURL,
			"ipv6_url":  cfg.IPv6CheckURL,
			"ipv6_urls": cfg.IPv6CheckURLs,
		})
	})

	r.GET("/api/my/network", func(c *gin.Context) {
		lang := c.DefaultQuery("lang", "zh")
		ip := clientIP(c)
		resp, err := agg.Query(ip, lang)
		if err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, resp)
	})

	r.GET("/api/nat/browser-config", func(c *gin.Context) {
		iceServers := make([]gin.H, 0, len(cfg.NATICEServers))
		stunProbes := make([]gin.H, 0, len(cfg.NATICEServers))
		for _, server := range cfg.NATICEServers {
			if len(server.URLs) == 0 {
				continue
			}

			hasTurnURL := false
			for _, rawURL := range server.URLs {
				if strings.HasPrefix(strings.ToLower(strings.TrimSpace(rawURL)), "turn:") || strings.HasPrefix(strings.ToLower(strings.TrimSpace(rawURL)), "turns:") {
					hasTurnURL = true
					break
				}
			}
			if hasTurnURL && (strings.TrimSpace(server.Username) == "" || strings.TrimSpace(server.Credential) == "") {
				continue
			}

			item := gin.H{"urls": server.URLs}
			if server.Username != "" {
				item["username"] = server.Username
			}
			if server.Credential != "" {
				item["credential"] = server.Credential
			}
			iceServers = append(iceServers, item)

			if !hasTurnURL {
				for _, rawURL := range server.URLs {
					trimmedURL := strings.TrimSpace(rawURL)
					if trimmedURL == "" {
						continue
					}
					stunProbes = append(stunProbes, gin.H{
						"label": trimmedURL,
						"urls":  []string{trimmedURL},
					})
				}
			}
		}

		c.JSON(200, gin.H{
			"ice_servers": iceServers,
			"stun_probes": stunProbes,
		})
	})

	r.GET("/api/nat/server-stun", func(c *gin.Context) {
		lang := c.DefaultQuery("lang", "zh")
		result := service.AnalyzeServerSTUN(c.Request.Context(), cfg.NATICEServers, lang)
		c.JSON(200, result)
	})

	r.POST("/api/nat/browser-report", func(c *gin.Context) {
		var req model.BrowserNATReportRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		lang := c.DefaultQuery("lang", "zh")
		result := service.AnalyzeBrowserNAT(req, lang)
		c.JSON(200, result)
	})

	r.Run(":8779")
}

func clientIP(c *gin.Context) string {
	for _, header := range []string{
		"CF-Connecting-IP",
		"True-Client-IP",
		"X-Client-IP",
		"Fastly-Client-IP",
		"CloudFront-Viewer-Address",
	} {
		if ip := firstValidIP(c.GetHeader(header)); ip != "" {
			return ip
		}
	}
	if ip := firstValidIP(c.GetHeader("X-Forwarded-For")); ip != "" {
		return ip
	}
	if ip := forwardedIP(c.GetHeader("Forwarded")); ip != "" {
		return ip
	}
	if ip := firstValidIP(c.GetHeader("X-Real-IP")); ip != "" {
		return ip
	}

	ip := c.ClientIP()
	if net.ParseIP(ip) != nil {
		return ip
	}
	return ""
}

func clientIPVersion(c *gin.Context, version int) string {
	for _, header := range []string{
		"CF-Connecting-IP",
		"True-Client-IP",
		"X-Client-IP",
		"Fastly-Client-IP",
		"CloudFront-Viewer-Address",
		"X-Forwarded-For",
		"X-Real-IP",
	} {
		if ip := firstValidIPVersion(c.GetHeader(header), version); ip != "" {
			return ip
		}
	}
	if ip := forwardedIPVersion(c.GetHeader("Forwarded"), version); ip != "" {
		return ip
	}

	ip := c.ClientIP()
	if ipMatchesVersion(ip, version) {
		return ip
	}
	return ""
}

func allowIPCheckCORS(c *gin.Context, methods ...string) {
	allowedMethods := http.MethodGet
	if len(methods) > 0 {
		allowedMethods = strings.Join(methods, ", ")
	}
	c.Header("Access-Control-Allow-Origin", "*")
	c.Header("Access-Control-Allow-Methods", allowedMethods)
	c.Header("Access-Control-Allow-Headers", "Content-Type")
}

func ensureIPCacheSession(c *gin.Context) string {
	if cookie, err := c.Cookie(ipCacheCookieName); err == nil && isValidSessionID(cookie) {
		return cookie
	}
	sessionID := newSessionID()
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     ipCacheCookieName,
		Value:    sessionID,
		Path:     "/",
		MaxAge:   defaultIPCacheMaxAgeSec,
		SameSite: http.SameSiteLaxMode,
		Secure:   c.Request.TLS != nil || strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https"),
		HttpOnly: true,
	})
	return sessionID
}

func newSessionID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

func isValidSessionID(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, ch := range value {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}

func (s *ipCacheStore) get(sessionID string) (cachedIPResult, cachedIPResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.entries[sessionID]
	if isExpiredCachedIP(entry.IPv4) {
		entry.IPv4 = cachedIPResult{}
	}
	if isExpiredCachedIP(entry.IPv6) {
		entry.IPv6 = cachedIPResult{}
	}
	if !entry.IPv4.Available && !entry.IPv6.Available {
		delete(s.entries, sessionID)
		return cachedIPResult{}, cachedIPResult{}
	}
	s.entries[sessionID] = entry
	return entry.IPv4, entry.IPv6
}

func (s *ipCacheStore) set(sessionID string, result cachedIPResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.entries[sessionID]
	if result.Version == 4 {
		entry.IPv4 = result
	}
	if result.Version == 6 {
		entry.IPv6 = result
	}
	entry.UpdatedAt = time.Now()
	s.entries[sessionID] = entry
	s.trimLocked(time.Now())
}

func (s *ipCacheStore) clearVersion(sessionID string, version int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.entries[sessionID]
	if version == 4 {
		entry.IPv4 = cachedIPResult{}
	}
	if version == 6 {
		entry.IPv6 = cachedIPResult{}
	}
	entry.UpdatedAt = time.Now()
	if !entry.IPv4.Available && !entry.IPv6.Available {
		delete(s.entries, sessionID)
		return
	}
	s.entries[sessionID] = entry
}

func isExpiredCachedIP(result cachedIPResult) bool {
	return result.Available && time.Since(result.CachedAt) > ipCacheTTL
}

func (s *ipCacheStore) startCleanup(interval time.Duration) func() {
	if interval <= 0 {
		return func() {}
	}
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.cleanupExpired(time.Now())
			case <-stop:
				return
			}
		}
	}()
	return func() { close(stop) }
}

func (s *ipCacheStore) cleanupExpired(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupExpiredLocked(now)
}

func (s *ipCacheStore) cleanupExpiredLocked(now time.Time) {
	for sessionID, entry := range s.entries {
		if isExpiredCachedIPAt(entry.IPv4, now) {
			entry.IPv4 = cachedIPResult{}
		}
		if isExpiredCachedIPAt(entry.IPv6, now) {
			entry.IPv6 = cachedIPResult{}
		}
		if !entry.IPv4.Available && !entry.IPv6.Available {
			delete(s.entries, sessionID)
			continue
		}
		s.entries[sessionID] = entry
	}
}

func (s *ipCacheStore) trimLocked(now time.Time) {
	s.cleanupExpiredLocked(now)
	if s.maxEntries <= 0 || len(s.entries) <= s.maxEntries {
		return
	}
	for len(s.entries) > s.maxEntries {
		oldestID := ""
		oldest := now
		for sessionID, entry := range s.entries {
			updated := entry.UpdatedAt
			if updated.IsZero() {
				updated = oldestCachedAt(entry)
			}
			if oldestID == "" || updated.Before(oldest) {
				oldestID = sessionID
				oldest = updated
			}
		}
		if oldestID == "" {
			return
		}
		delete(s.entries, oldestID)
	}
}

func oldestCachedAt(entry ipCacheEntry) time.Time {
	if entry.IPv4.Available && entry.IPv6.Available {
		if entry.IPv4.CachedAt.Before(entry.IPv6.CachedAt) {
			return entry.IPv4.CachedAt
		}
		return entry.IPv6.CachedAt
	}
	if entry.IPv4.Available {
		return entry.IPv4.CachedAt
	}
	if entry.IPv6.Available {
		return entry.IPv6.CachedAt
	}
	return time.Time{}
}

func isExpiredCachedIPAt(result cachedIPResult, now time.Time) bool {
	return result.Available && now.Sub(result.CachedAt) > ipCacheTTL
}

func dualIPResponse(c *gin.Context, cache *ipCacheStore) gin.H {
	ip := clientIP(c)
	version := service.DetectIPVersion(ip)
	sessionID := ensureIPCacheSession(c)
	ipv4 := ipVersionResult(clientIPVersion(c, 4), 4, "current_request")
	ipv6 := ipVersionResult(clientIPVersion(c, 6), 6, "current_request")
	if cache != nil {
		cachedIPv4, cachedIPv6 := cache.get(sessionID)
		if ipv4["available"] == true && cachedIPv4.Available && ipv4["ip"] != cachedIPv4.IP {
			cachedIPv6 = cachedIPResult{}
			cache.clearVersion(sessionID, 6)
		}
		if ipv6["available"] == true && cachedIPv6.Available && ipv6["ip"] != cachedIPv6.IP {
			cachedIPv4 = cachedIPResult{}
			cache.clearVersion(sessionID, 4)
		}
		if ipv4["available"] != true && cachedIPv4.Available {
			ipv4 = cachedIPResultH(cachedIPv4)
		}
		if ipv6["available"] != true && cachedIPv6.Available {
			ipv6 = cachedIPResultH(cachedIPv6)
		}
	}
	return gin.H{
		"ip":         ip,
		"ip_version": version,
		"current": gin.H{
			"ip":         ip,
			"ip_version": version,
			"is_ipv4":    version == "IPv4",
			"is_ipv6":    version == "IPv6",
		},
		"ipv4":       ipv4,
		"ipv6":       ipv6,
		"dual_stack": ipv4["available"] == true && ipv6["available"] == true,
	}
}

func ipVersionResult(ip string, version int, source string) gin.H {
	parsed := net.ParseIP(ip)
	if parsed == nil || (version == 4 && parsed.To4() == nil) || (version == 6 && parsed.To4() != nil) {
		return gin.H{
			"ip":         "",
			"ip_version": "",
			"available":  false,
		}
	}

	return gin.H{
		"ip":         ip,
		"ip_version": ipVersionLabel(version),
		"version":    version,
		"available":  true,
		"source":     source,
	}
}

func ipVersionLabel(version int) string {
	if version == 4 {
		return "IPv4"
	}
	if version == 6 {
		return "IPv6"
	}
	return ""
}

func cachedIPResultH(result cachedIPResult) gin.H {
	return gin.H{
		"ip":         result.IP,
		"ip_version": result.IPVersion,
		"version":    result.Version,
		"available":  result.Available,
		"source":     result.Source,
		"cached_at":  result.CachedAt.Format(time.RFC3339),
	}
}

func cachedIPv6APIResponse(result cachedIPResult) gin.H {
	return gin.H{
		"ip":         result.IP,
		"ip_version": "IPv6",
		"ipv4":       false,
		"ipv6":       result.IP,
		"version":    6,
		"is_ipv4":    false,
		"is_ipv6":    true,
		"available":  true,
		"source":     "cache",
		"cached_at":  result.CachedAt.Format(time.RFC3339),
	}
}

func firstValidIP(value string) string {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" || strings.EqualFold(part, "unknown") {
			continue
		}
		part = strings.Trim(part, "\"")
		if host, _, err := net.SplitHostPort(part); err == nil {
			part = strings.TrimSpace(host)
		}
		if net.ParseIP(part) != nil {
			return part
		}
	}
	return ""
}

func firstValidIPVersion(value string, version int) string {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" || strings.EqualFold(part, "unknown") {
			continue
		}
		part = strings.Trim(part, "\"")
		if host, _, err := net.SplitHostPort(part); err == nil {
			part = strings.TrimSpace(host)
		}
		if ipMatchesVersion(part, version) {
			return part
		}
	}
	return ""
}

func forwardedIP(value string) string {
	for _, group := range strings.Split(value, ",") {
		for _, field := range strings.Split(group, ";") {
			key, val, ok := strings.Cut(strings.TrimSpace(field), "=")
			if !ok || !strings.EqualFold(strings.TrimSpace(key), "for") {
				continue
			}
			val = strings.Trim(strings.TrimSpace(val), "\"")
			if strings.HasPrefix(val, "[") {
				if end := strings.Index(val, "]"); end >= 0 {
					val = val[1:end]
				}
			}
			if ip := firstValidIP(val); ip != "" {
				return ip
			}
		}
	}
	return ""
}

func forwardedIPVersion(value string, version int) string {
	for _, group := range strings.Split(value, ",") {
		for _, field := range strings.Split(group, ";") {
			key, val, ok := strings.Cut(strings.TrimSpace(field), "=")
			if !ok || !strings.EqualFold(strings.TrimSpace(key), "for") {
				continue
			}
			val = strings.Trim(strings.TrimSpace(val), "\"")
			if strings.HasPrefix(val, "[") {
				if end := strings.Index(val, "]"); end >= 0 {
					val = val[1:end]
				}
			}
			if ip := firstValidIPVersion(val, version); ip != "" {
				return ip
			}
		}
	}
	return ""
}

func ipMatchesVersion(value string, version int) bool {
	ip := net.ParseIP(value)
	if ip == nil {
		return false
	}
	if version == 4 {
		return ip.To4() != nil
	}
	if version == 6 {
		return ip.To4() == nil
	}
	return false
}

func wantsHTML(c *gin.Context) bool {
	accept := strings.ToLower(c.GetHeader("Accept"))
	ua := strings.ToLower(c.GetHeader("User-Agent"))
	if strings.Contains(ua, "curl") || strings.Contains(ua, "wget") || strings.Contains(ua, "httpie") {
		return false
	}
	return accept == "" || strings.Contains(accept, "text/html")
}

func wantsPlainIP(c *gin.Context) bool {
	ua := strings.ToLower(c.GetHeader("User-Agent"))
	return strings.Contains(ua, "curl") || strings.Contains(ua, "wget") || strings.Contains(ua, "httpie")
}

func dualIPPlainText(resp gin.H) string {
	parts := make([]string, 0, 2)
	if ipv4, ok := resp["ipv4"].(gin.H); ok && ipv4["available"] == true {
		if ip, ok := ipv4["ip"].(string); ok && ip != "" {
			parts = append(parts, ip)
		}
	}
	if ipv6, ok := resp["ipv6"].(gin.H); ok && ipv6["available"] == true {
		if ip, ok := ipv6["ip"].(string); ok && ip != "" {
			parts = append(parts, ip)
		}
	}
	if len(parts) == 0 {
		if ip, ok := resp["ip"].(string); ok {
			return ip + "\n"
		}
		return "\n"
	}
	return strings.Join(parts, "\n") + "\n"
}

func toolPageMeta(slug string) gin.H {
	titles := map[string]string{
		"network-ip-calculator":   "网络和 IP 地址计算器",
		"ipv4-representations":    "IPv4 地址表示转换器",
		"ipv6-nat64":              "IPv6 NAT64 地址转换器",
		"ipv4-range-to-cidr":      "IPv4 范围转 CIDR",
		"cidr-aggregator":         "CIDR 聚合器",
		"ipv4-cidr-to-netmask":    "IPv4 CIDR 与子网掩码转换",
		"ipv6-range-to-cidr":      "IPv6 范围转 CIDR",
		"ipv4-wildcard-mask":      "IPv4 通配符掩码计算器",
		"ipv4-subnet-calculator":  "IPv4 子网计算器",
		"ipv6-subnet-calculator":  "IPv6 子网计算器",
		"ipv6-expand-compress":    "IPv6 展开 / 压缩工具",
		"address-count-by-prefix": "按前缀长度计算地址数量",
		"cidr-to-ip-range":        "CIDR 转 IP 范围",
		"netmask-to-cidr":         "子网掩码转 CIDR",
		"ipv6-cidr-to-range":      "IPv6 CIDR 转范围",
		"ip-address-type":         "IP 地址类型判断",
		"ip-validator":            "IPv4 / IPv6 验证器",
		"reverse-dns-generator":   "反向 DNS 名称生成器",
		"subnet-splitter":         "子网拆分器",
		"bulk-ip-calculator":      "IP 地址批量计算",
	}
	title := titles[slug]
	if title == "" {
		title = "IP 工具"
	}
	return gin.H{
		"Title":       title + " - IP Network Tools",
		"Description": title + "，在线本地计算 IPv4、IPv6、CIDR、子网和地址范围。",
	}
}

func writeIPImage(c *gin.Context, ip string, location string) {
	if strings.TrimSpace(ip) == "" {
		ip = "Unknown"
	}
	if strings.TrimSpace(location) == "" {
		location = "NetScope"
	}

	svg := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 215 70" role="img" aria-label="my ip address">
  <defs>
    <style type="text/css">
      @font-face {
        font-family: 'Roboto';
        font-style: normal;
        font-weight: 400;
        font-stretch: 100%;
        font-display: swap;
        src: url(https://fonts.gstatic.com/s/roboto/v51/KFO7CnqEu92Fr1ME7kSn66aGLdTylUAMa3yUBA.woff2) format('woff2');
        unicode-range: U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;
      }
      @font-face {
        font-family: 'Roboto';
        font-style: normal;
        font-weight: 700;
        font-stretch: 100%;
        font-display: swap;
        src: url(https://fonts.gstatic.com/s/roboto/v51/KFO7CnqEu92Fr1ME7kSn66aGLdTylUAMa3yUBA.woff2) format('woff2');
        unicode-range: U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;
      }
    </style>
  </defs>
  <rect width="215" height="70" fill="white" stroke="black" stroke-width="1"/>
  <text x="10" y="20" font-family="'Roboto', sans-serif" font-size="14" fill="black">What is my IP address?</text>
  <text x="10" y="45" font-family="'Roboto', sans-serif" font-size="24" font-weight="700" fill="black">__IP__</text>
  <a href="https://ip.boxove.com" target="_blank">
    <text x="12" y="60" font-family="'Roboto', sans-serif" font-size="8" fill="#666">__LOCATION__ - NetScope</text>
  </a>
</svg>`
	svg = strings.ReplaceAll(svg, "__IP__", html.EscapeString(ip))
	svg = strings.ReplaceAll(svg, "__LOCATION__", html.EscapeString(location))

	c.Header("Cache-Control", "no-store")
	c.Data(http.StatusOK, "image/svg+xml; charset=utf-8", []byte(svg))
}

func imageLocation(resp *model.QueryResponse) string {
	if resp == nil {
		return "NetScope"
	}
	parts := make([]string, 0, 4)
	for _, part := range []string{
		resp.Location.City,
		resp.Location.Region,
		resp.Location.CountryCode,
		resp.Location.Country,
	} {
		part = strings.TrimSpace(part)
		if part != "" {
			parts = append(parts, part)
		}
	}
	if len(parts) == 0 {
		return "NetScope"
	}
	return strings.Join(parts, " ")
}

func trustedProxiesFromEnv() []string {
	value := strings.TrimSpace(os.Getenv(trustedProxiesEnv))
	if value == "" {
		return []string{"127.0.0.1", "::1"}
	}
	if strings.EqualFold(value, "none") {
		return nil
	}

	parts := strings.Split(value, ",")
	proxies := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			proxies = append(proxies, part)
		}
	}
	return proxies
}

func loadDotEnv() {
	paths := []string{".env"}

	if exePath, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exePath)
		paths = append(paths, filepath.Join(exeDir, ".env"))
	}

	for _, p := range paths {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			_ = godotenv.Overload(p)
		}
	}
}
