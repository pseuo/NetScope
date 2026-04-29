package main

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestTrustedProxiesFromEnv(t *testing.T) {
	t.Setenv(trustedProxiesEnv, "")
	if got := trustedProxiesFromEnv(); !reflect.DeepEqual(got, []string{"127.0.0.1", "::1"}) {
		t.Fatalf("default trusted proxies = %#v", got)
	}

	t.Setenv(trustedProxiesEnv, "10.0.0.0/8, 192.0.2.10")
	if got := trustedProxiesFromEnv(); !reflect.DeepEqual(got, []string{"10.0.0.0/8", "192.0.2.10"}) {
		t.Fatalf("env trusted proxies = %#v", got)
	}

	t.Setenv(trustedProxiesEnv, "none")
	if got := trustedProxiesFromEnv(); got != nil {
		t.Fatalf("none trusted proxies = %#v", got)
	}
}

func TestClientIPPrefersForwardHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Request.RemoteAddr = "203.0.113.9:12345"
	c.Request.Header.Set("X-Forwarded-For", "unknown, 198.51.100.8, 203.0.113.1")

	if got := clientIP(c); got != "198.51.100.8" {
		t.Fatalf("clientIP() = %q", got)
	}
}

func TestForwardedIPParsesQuotedIPv6WithPort(t *testing.T) {
	value := `for="[2001:db8::1]:443";proto=https, for=198.51.100.2`
	if got := forwardedIP(value); got != "2001:db8::1" {
		t.Fatalf("forwardedIP() = %q", got)
	}
}

func TestIPCacheStoreTrimsAndCleansExpiredEntries(t *testing.T) {
	store := newIPCacheStore()
	store.maxEntries = 2
	now := time.Now()

	store.set("old", cachedIPResult{IP: "192.0.2.1", IPVersion: "IPv4", Version: 4, Available: true, CachedAt: now})
	store.entries["old"] = ipCacheEntry{IPv4: store.entries["old"].IPv4, UpdatedAt: now.Add(-time.Minute)}
	store.set("newer", cachedIPResult{IP: "192.0.2.2", IPVersion: "IPv4", Version: 4, Available: true, CachedAt: now})
	store.set("newest", cachedIPResult{IP: "192.0.2.3", IPVersion: "IPv4", Version: 4, Available: true, CachedAt: now})

	if _, ok := store.entries["old"]; ok {
		t.Fatalf("oldest cache entry was not trimmed")
	}
	if len(store.entries) != 2 {
		t.Fatalf("cache entry count = %d", len(store.entries))
	}

	store.entries["expired"] = ipCacheEntry{
		IPv4:     cachedIPResult{IP: "192.0.2.4", IPVersion: "IPv4", Version: 4, Available: true, CachedAt: now.Add(-2 * ipCacheTTL)},
		UpdatedAt: now,
	}
	store.cleanupExpired(now)
	if _, ok := store.entries["expired"]; ok {
		t.Fatalf("expired cache entry was not cleaned")
	}
}
