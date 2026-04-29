package service

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"ip-query/config"
	"ip-query/model"
)

const (
	stunBindingRequest  = 0x0001
	stunBindingResponse = 0x0101
	stunXORMappedAddr   = 0x0020
	stunMappedAddr      = 0x0001
	stunMagicCookie     = 0x2112A442
)

type STUNProbeResult struct {
	Server       string `json:"server"`
	MappedIP     string `json:"mapped_ip,omitempty"`
	MappedPort   int    `json:"mapped_port,omitempty"`
	LocalAddress string `json:"local_address,omitempty"`
	Error        string `json:"error,omitempty"`
}

type ServerSTUNResult struct {
	NATInfo model.NATInfo     `json:"nat"`
	Probes  []STUNProbeResult `json:"probes"`
}

func AnalyzeServerSTUN(ctx context.Context, servers []config.NATICEServerConfig, lang string) ServerSTUNResult {
	urls := stunURLsFromConfig(servers)
	probes := make([]STUNProbeResult, 0, len(urls))
	for _, rawURL := range urls {
		probe, err := runSTUNProbe(ctx, rawURL, 2500*time.Millisecond)
		if err != nil {
			probe = STUNProbeResult{Server: rawURL, Error: err.Error()}
		}
		probes = append(probes, probe)
	}

	nat := model.NATInfo{
		Detected:       true,
		TypeCode:       "unknown",
		TypeName:       "Unknown",
		TypeNameZH:     "未知",
		Confidence:     "low",
		Method:         "server-stun-binding",
		Description:    localize(lang, "后端 STUN 探测未获得足够结果", "Server-side STUN probing did not collect enough evidence"),
		ConnectionMode: "unknown",
	}

	mappings := make(map[string]struct{})
	for _, probe := range probes {
		if probe.MappedIP == "" || probe.MappedPort <= 0 {
			continue
		}
		if nat.PublicIP == "" {
			nat.PublicIP = probe.MappedIP
			nat.PublicPort = probe.MappedPort
		}
		mappings[probe.MappedIP+":"+strconv.Itoa(probe.MappedPort)] = struct{}{}
	}

	successCount := len(mappings)
	switch {
	case successCount == 0:
		nat.TypeCode = "udp_blocked"
		nat.TypeName = "UDP Blocked or STUN Unavailable"
		nat.TypeNameZH = "UDP 受限或 STUN 不可用"
		nat.ConnectionMode = "unknown"
		nat.Confidence = "medium"
		nat.HasNAT = boolPtr(true)
		nat.Description = localize(lang,
			"后端无法从任何 STUN 服务器获得公网映射，可能是服务器出口 UDP 被限制、STUN 服务器不可达，或网络策略阻断",
			"The backend could not obtain a public mapping from any STUN server; outbound UDP may be restricted, STUN servers may be unreachable, or a network policy may block probing",
		)
	case successCount > 1:
		nat.TypeCode = "symmetric"
		nat.TypeName = "Symmetric NAT Suspected"
		nat.TypeNameZH = "疑似对称型 NAT"
		nat.ConnectionMode = "mapped"
		nat.Confidence = "medium"
		nat.HasNAT = boolPtr(true)
		nat.Description = localize(lang,
			"多个 STUN 服务器返回了不同公网映射，特征符合或接近对称型 NAT",
			"Multiple STUN servers returned different public mappings, which is consistent with or close to symmetric NAT behavior",
		)
	default:
		nat.TypeCode = "cone"
		nat.TypeName = "Non-Symmetric NAT / Public Mapping Stable"
		nat.TypeNameZH = "非对称型 NAT / 公网映射稳定"
		nat.ConnectionMode = "mapped"
		nat.Confidence = "low"
		nat.HasNAT = boolPtr(true)
		nat.Description = localize(lang,
			"多个后端 STUN 探测得到稳定公网映射，未发现对称型 NAT 特征；仅凭公共 STUN 不能继续细分完全锥形、受限锥形或端口受限锥形",
			"Server-side STUN probes observed a stable public mapping and no symmetric NAT behavior; public STUN alone cannot further distinguish full cone, restricted cone, or port-restricted cone NAT",
		)
	}

	return ServerSTUNResult{NATInfo: nat, Probes: probes}
}

func stunURLsFromConfig(servers []config.NATICEServerConfig) []string {
	seen := make(map[string]struct{})
	out := []string{}
	for _, server := range servers {
		for _, rawURL := range server.URLs {
			rawURL = strings.TrimSpace(rawURL)
			if !strings.HasPrefix(strings.ToLower(rawURL), "stun:") {
				continue
			}
			if _, ok := seen[rawURL]; ok {
				continue
			}
			seen[rawURL] = struct{}{}
			out = append(out, rawURL)
		}
	}
	return out
}

func runSTUNProbe(ctx context.Context, rawURL string, timeout time.Duration) (STUNProbeResult, error) {
	server, err := parseSTUNServer(rawURL)
	if err != nil {
		return STUNProbeResult{Server: rawURL}, err
	}

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "udp", server)
	if err != nil {
		return STUNProbeResult{Server: rawURL}, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	req, txID, err := buildSTUNBindingRequest()
	if err != nil {
		return STUNProbeResult{Server: rawURL}, err
	}
	if _, err := conn.Write(req); err != nil {
		return STUNProbeResult{Server: rawURL}, err
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return STUNProbeResult{Server: rawURL}, err
	}
	ip, port, err := parseSTUNBindingResponse(buf[:n], txID)
	if err != nil {
		return STUNProbeResult{Server: rawURL}, err
	}

	localAddr := ""
	if addr := conn.LocalAddr(); addr != nil {
		localAddr = addr.String()
	}
	return STUNProbeResult{Server: rawURL, MappedIP: ip, MappedPort: port, LocalAddress: localAddr}, nil
}

func parseSTUNServer(rawURL string) (string, error) {
	trimmed := strings.TrimSpace(rawURL)
	if strings.HasPrefix(strings.ToLower(trimmed), "stun:") {
		trimmed = trimmed[5:]
	}
	if strings.Contains(trimmed, "?") {
		parsed, err := url.Parse("stun://" + trimmed)
		if err != nil {
			return "", err
		}
		trimmed = parsed.Host
	}
	if trimmed == "" {
		return "", errors.New("empty STUN server")
	}
	if _, _, err := net.SplitHostPort(trimmed); err == nil {
		return trimmed, nil
	}
	return net.JoinHostPort(trimmed, "3478"), nil
}

func buildSTUNBindingRequest() ([]byte, [12]byte, error) {
	var txID [12]byte
	if _, err := rand.Read(txID[:]); err != nil {
		return nil, txID, err
	}
	msg := make([]byte, 20)
	binary.BigEndian.PutUint16(msg[0:2], stunBindingRequest)
	binary.BigEndian.PutUint16(msg[2:4], 0)
	binary.BigEndian.PutUint32(msg[4:8], stunMagicCookie)
	copy(msg[8:20], txID[:])
	return msg, txID, nil
}

func parseSTUNBindingResponse(msg []byte, txID [12]byte) (string, int, error) {
	if len(msg) < 20 {
		return "", 0, errors.New("short STUN response")
	}
	if binary.BigEndian.Uint16(msg[0:2]) != stunBindingResponse {
		return "", 0, fmt.Errorf("unexpected STUN response type 0x%04x", binary.BigEndian.Uint16(msg[0:2]))
	}
	if binary.BigEndian.Uint32(msg[4:8]) != stunMagicCookie {
		return "", 0, errors.New("invalid STUN magic cookie")
	}
	if string(msg[8:20]) != string(txID[:]) {
		return "", 0, errors.New("STUN transaction ID mismatch")
	}

	attrsLen := int(binary.BigEndian.Uint16(msg[2:4]))
	if 20+attrsLen > len(msg) {
		return "", 0, errors.New("truncated STUN attributes")
	}
	for offset := 20; offset+4 <= 20+attrsLen; {
		attrType := binary.BigEndian.Uint16(msg[offset : offset+2])
		attrLen := int(binary.BigEndian.Uint16(msg[offset+2 : offset+4]))
		valueStart := offset + 4
		valueEnd := valueStart + attrLen
		if valueEnd > len(msg) {
			return "", 0, errors.New("truncated STUN attribute")
		}
		if attrType == stunXORMappedAddr || attrType == stunMappedAddr {
			return parseSTUNAddress(attrType, msg[valueStart:valueEnd], txID)
		}
		offset = valueEnd + ((4 - (attrLen % 4)) % 4)
	}
	return "", 0, errors.New("missing STUN mapped address")
}

func parseSTUNAddress(attrType uint16, value []byte, txID [12]byte) (string, int, error) {
	if len(value) < 4 {
		return "", 0, errors.New("short STUN address attribute")
	}
	family := value[1]
	port := binary.BigEndian.Uint16(value[2:4])
	if attrType == stunXORMappedAddr {
		port ^= uint16(stunMagicCookie >> 16)
	}
	switch family {
	case 0x01:
		if len(value) < 8 {
			return "", 0, errors.New("short IPv4 STUN address")
		}
		ipBytes := append([]byte(nil), value[4:8]...)
		if attrType == stunXORMappedAddr {
			cookie := make([]byte, 4)
			binary.BigEndian.PutUint32(cookie, stunMagicCookie)
			for i := range ipBytes {
				ipBytes[i] ^= cookie[i]
			}
		}
		return net.IP(ipBytes).String(), int(port), nil
	case 0x02:
		if len(value) < 20 {
			return "", 0, errors.New("short IPv6 STUN address")
		}
		ipBytes := append([]byte(nil), value[4:20]...)
		if attrType == stunXORMappedAddr {
			cookieAndTx := make([]byte, 16)
			binary.BigEndian.PutUint32(cookieAndTx[0:4], stunMagicCookie)
			copy(cookieAndTx[4:], txID[:])
			for i := range ipBytes {
				ipBytes[i] ^= cookieAndTx[i]
			}
		}
		return net.IP(ipBytes).String(), int(port), nil
	default:
		return "", 0, fmt.Errorf("unsupported STUN address family %d", family)
	}
}
