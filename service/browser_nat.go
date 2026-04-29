package service

import (
	"net"
	"strconv"
	"strings"

	"ip-query/model"
)

type probeSummary struct {
	Label      string
	HasHost    bool
	HasSrflx   bool
	HasRelay   bool
	Srflx      []model.ICECandidateInfo
	Selected   model.ICECandidateInfo
	Connection string
}

func AnalyzeBrowserNAT(req model.BrowserNATReportRequest, lang string) model.NATInfo {
	var hostCandidates []model.ICECandidateInfo
	var srflxCandidates []model.ICECandidateInfo
	var relayCandidates []model.ICECandidateInfo

	ipv4Supported := false
	ipv6Supported := false

	for _, c := range req.Candidates {
		addr := strings.TrimSpace(c.Address)
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}

		if ip.To4() == nil {
			ipv6Supported = true
		} else {
			ipv4Supported = true
		}
	}

	for _, c := range req.Candidates {
		switch strings.ToLower(strings.TrimSpace(c.Type)) {
		case "host":
			hostCandidates = append(hostCandidates, c)
		case "srflx":
			srflxCandidates = append(srflxCandidates, c)
		case "relay":
			relayCandidates = append(relayCandidates, c)
		}
	}

	for _, probe := range req.Probes {
		for _, c := range probe.Candidates {
			ip := net.ParseIP(strings.TrimSpace(c.Address))
			if ip == nil {
				continue
			}
			if ip.To4() == nil {
				ipv6Supported = true
			} else {
				ipv4Supported = true
			}
		}
	}

	result := model.NATInfo{
		Detected:        true,
		Method:          "webrtc-ice-multi-stun",
		IPv4Supported:   ipv4Supported,
		IPv6Supported:   ipv6Supported,
		TypeCode:        "unknown",
		TypeName:        "Unknown",
		TypeNameZH:      "未知",
		Confidence:      "low",
		Description:     localize(lang, "无法从当前浏览器 ICE 结果判断网络路径", "Unable to classify the current browser network path from ICE results"),
		LocalIP:         detectLocalIP(hostCandidates, req.SelectedLocalCandidate),
		PublicIP:        detectPublicIP(srflxCandidates, req.SelectedLocalCandidate, req.SelectedRemoteCandidate),
		PublicPort:      detectPublicPort(srflxCandidates, req.SelectedLocalCandidate, req.SelectedRemoteCandidate),
		GatheringState:  strings.TrimSpace(req.GatheringState),
		SelectedType:    strings.TrimSpace(req.SelectedCandidateType),
		RelayAvailable:  len(relayCandidates) > 0,
		DirectAvailable: len(hostCandidates) > 0 || len(srflxCandidates) > 0,
		ConnectionMode:  "unknown",
	}
	if strings.TrimSpace(result.PublicIP) == "" && isPublicIP(req.HTTPPublicIP) {
		result.PublicIP = strings.TrimSpace(req.HTTPPublicIP)
	}

	selectedLocalType := strings.ToLower(strings.TrimSpace(req.SelectedLocalCandidate.Type))
	selectedRemoteType := strings.ToLower(strings.TrimSpace(req.SelectedRemoteCandidate.Type))
	selectedType := strings.ToLower(strings.TrimSpace(req.SelectedCandidateType))
	iceState := strings.ToLower(strings.TrimSpace(req.ICEConnectionState))
	connState := strings.ToLower(strings.TrimSpace(req.ConnectionState))
	probeSummaries := summarizeProbes(req)
	symmetricNAT := isSymmetricNAT(srflxCandidates) || isSymmetricAcrossProbes(probeSummaries) || hasMultipleSrflxMappingsInSingleProbe(probeSummaries)
	portConsistentAcrossProbes := isConsistentMappingAcrossProbes(probeSummaries)
	hasSrflxAcrossProbes := hasSrflxProbe(probeSummaries)
	hasPublicHost := hasPublicHostCandidate(hostCandidates)
	hasPrivateHost := hasPrivateHostCandidate(hostCandidates)
	hasMaskedHost := hasMaskedHostCandidate(hostCandidates)
	hasUsableLocalIP := strings.TrimSpace(result.LocalIP) != ""
	hasUsablePublicIP := strings.TrimSpace(detectPublicIP(srflxCandidates, req.SelectedLocalCandidate, req.SelectedRemoteCandidate)) != ""

	connected := isConnectedState(iceState) || isConnectedState(connState)
	relaySelected := selectedType == "relay" || selectedLocalType == "relay" || selectedRemoteType == "relay"
	directSelected := selectedType == "host" || selectedType == "srflx" || selectedLocalType == "host" || selectedLocalType == "srflx"
	directAvailable := hasUsableHostCandidate(hostCandidates) || len(srflxCandidates) > 0 || hasSrflxAcrossProbes
	hasDirectEvidence := hasUsableLocalIP || hasUsablePublicIP || hasPublicHost || hasSrflxAcrossProbes
	relayAvailable := len(relayCandidates) > 0

	observedNAT := hasNAT(srflxCandidates)
	if observedNAT {
		result.HasNAT = boolPtr(true)
	}

	switch {
	case connected && directSelected && hasPublicHost && !hasPrivateHost && !observedNAT:
		result.TypeCode = "open"
		result.TypeName = "Open Internet"
		result.TypeNameZH = "开放网络"
		result.ConnectionMode = "direct"
		result.Confidence = "medium"
		result.HasNAT = boolPtr(false)
		result.Description = localize(lang,
			"浏览器拿到了公网 host 候选，且没有观察到 server-reflexive 映射，当前网络更接近开放网络或公网直连",
			"The browser exposed a public host candidate without a separate server-reflexive mapping, which is closer to open internet or direct public connectivity",
		)
		return result
	case symmetricNAT:
		result.TypeCode = "symmetric"
		result.TypeName = "Symmetric NAT"
		result.TypeNameZH = "对称型 NAT"
		result.ConnectionMode = "mapped"
		result.Confidence = "high"
		result.HasNAT = boolPtr(true)
		result.Description = localize(lang,
			"同一本地地址/端口在 ICE 结果中映射出了多个公网端口，特征更接近对称型 NAT",
			"The same local endpoint was mapped to multiple server-reflexive ports in ICE results, which is characteristic of symmetric NAT",
		)
		return result
	case hasSrflxAcrossProbes && portConsistentAcrossProbes && connected && directSelected:
		result.TypeCode = "full_cone"
		result.TypeName = "Full Cone NAT"
		result.TypeNameZH = "完全锥形 NAT"
		result.ConnectionMode = "mapped"
		result.Confidence = "medium"
		result.HasNAT = boolPtr(true)
		result.Description = localize(lang,
			"多个 STUN 探测点返回了稳定一致的公网映射，且当前自连路径可直通，特征更接近完全锥形 NAT",
			"Multiple STUN probes returned a stable public mapping and the current self-connectivity remained direct, which is more consistent with full cone NAT",
		)
		return result
	case hasSrflxAcrossProbes && portConsistentAcrossProbes && directAvailable && !relayAvailable:
		result.TypeCode = "restricted_cone"
		result.TypeName = "Restricted Cone NAT"
		result.TypeNameZH = "受限锥形 NAT"
		result.ConnectionMode = "mapped"
		if connected && directSelected {
			result.ConnectionMode = "direct"
		}
		result.Confidence = "low"
		result.HasNAT = boolPtr(true)
		result.Description = localize(lang,
			"多个 STUN 探测点返回了稳定一致的公网映射，但浏览器侧缺少足够行为测试来区分来源地址限制，当前结果更偏向受限锥形 NAT",
			"Multiple STUN probes returned a stable public mapping, but browser-side testing cannot fully validate address filtering behavior; the result currently leans toward restricted cone NAT",
		)
		return result
	case hasSrflxAcrossProbes && portConsistentAcrossProbes:
		result.TypeCode = "port_restricted"
		result.TypeName = "Port Restricted Cone NAT"
		result.TypeNameZH = "端口受限锥形 NAT"
		result.ConnectionMode = "mapped"
		if relayAvailable && !connected {
			result.ConnectionMode = "relay"
		}
		result.Confidence = "low"
		result.HasNAT = boolPtr(true)
		result.Description = localize(lang,
			"多个 STUN 探测点返回了稳定一致的公网映射，但直连行为受限或更依赖中继，当前结果更偏向端口受限锥形 NAT",
			"Multiple STUN probes returned a stable public mapping, but direct connectivity remained limited or leaned on relay, so the result currently leans toward port-restricted cone NAT",
		)
		return result
	case hasSrflxAcrossProbes && portConsistentAcrossProbes:
		result.TypeCode = "cone"
		result.TypeName = "Non-Symmetric NAT / Public Mapping Stable"
		result.TypeNameZH = "非对称型 NAT / 公网映射稳定"
		result.ConnectionMode = "mapped"
		result.Confidence = "low"
		result.HasNAT = boolPtr(true)
		result.Description = localize(lang,
			"浏览器通过 STUN 获取到了稳定公网映射，未观察到对称型 NAT 特征；仅凭公共 STUN 不能继续细分完全锥形、受限锥形或端口受限锥形",
			"The browser obtained a stable public mapping via STUN and no symmetric NAT behavior was observed; public STUN alone cannot further distinguish full cone, restricted cone, or port-restricted cone NAT",
		)
		return result
	case !hasSrflxAcrossProbes && relayAvailable:
		result.TypeCode = "udp_blocked"
		result.TypeName = "UDP Blocked / Relay Only"
		result.TypeNameZH = "UDP 被限制 / 仅能中继"
		result.ConnectionMode = "relay"
		result.Confidence = "high"
		result.HasNAT = boolPtr(true)
		result.Description = localize(lang,
			"多个 STUN 探测点都未能拿到 server-reflexive 映射，但 TURN relay 可用，网络更像是 UDP 被拦截或强限制",
			"Multiple STUN probes failed to obtain server-reflexive mappings while TURN relay remained available, suggesting UDP is blocked or heavily restricted",
		)
		return result
	case !hasSrflxAcrossProbes && !relayAvailable && connected && directSelected && hasPublicHost && !hasPrivateHost:
		result.TypeCode = "open"
		result.TypeName = "Open Internet"
		result.TypeNameZH = "开放网络"
		result.ConnectionMode = "direct"
		result.Confidence = "low"
		result.HasNAT = boolPtr(false)
		result.Description = localize(lang,
			"没有观察到 NAT 映射，且浏览器可直接使用公网 host 候选，网络更接近开放网络",
			"No NAT mapping was observed and the browser could use a public host candidate directly, which is closer to open internet",
		)
		return result
	case hasSrflxAcrossProbes:
		result.TypeCode = "cone"
		result.TypeName = "Cone NAT / Type Undetermined"
		result.TypeNameZH = "锥形 NAT / 类型待细分"
		result.ConnectionMode = "mapped"
		result.Confidence = "low"
		result.HasNAT = boolPtr(true)
		result.Description = localize(lang,
			"浏览器已通过 STUN 获取到 server-reflexive 公网映射，但本地关联地址或跨服务器一致性证据不足，只能确认存在 NAT，无法进一步区分完全锥形、受限锥形或端口受限锥形",
			"The browser obtained a server-reflexive public mapping via STUN, but local related-address or cross-server consistency evidence is insufficient; NAT is present, but the exact cone subtype cannot be determined",
		)
		return result
	case connected && directSelected && (hasPrivateHost || hasMaskedHost) && !hasSrflxAcrossProbes && !hasUsablePublicIP:
		result.TypeCode = "webrtc_srflx_unavailable"
		result.TypeName = "WebRTC STUN Mapping Unavailable"
		result.TypeNameZH = "浏览器未暴露 STUN 公网映射"
		result.ConnectionMode = "local"
		result.Confidence = "low"
		result.Description = localize(lang,
			"浏览器 ICE 只返回了 mDNS 隐藏的 host 候选，没有返回 server-reflexive 公网映射；HTTP 可看到当前公网 IP，但无法据此判断 NAT 类型",
			"Browser ICE returned only mDNS-masked host candidates and no server-reflexive public mapping; HTTP can show the current public IP, but that is not enough to classify the NAT type",
		)
		return result
	case connected && directSelected && hasDirectEvidence:
		result.TypeCode = "direct"
		result.TypeName = "Direct Connectivity"
		result.TypeNameZH = "直连"
		result.ConnectionMode = "direct"
		result.Confidence = "medium"
		result.Description = localize(lang,
			"ICE 已建立直连路径，且拿到了可用的 host 或 srflx 证据",
			"ICE established a direct path with usable host or srflx evidence",
		)
		return result
	case connected && directSelected:
		result.TypeCode = "unknown"
		result.TypeName = "Unknown"
		result.TypeNameZH = "未知"
		result.ConnectionMode = "unknown"
		result.Confidence = "low"
		result.Description = localize(lang,
			"浏览器内部 ICE 自连成功，但没有收集到足够的本地或公网候选证据，无法据此判定为真正直连",
			"The browser's internal ICE self-connectivity succeeded, but there was not enough local or public candidate evidence to classify it as true direct connectivity",
		)
		return result
	case connected && relaySelected:
		result.TypeCode = "relay"
		result.TypeName = "Relay via TURN"
		result.TypeNameZH = "TURN 中继"
		result.ConnectionMode = "relay"
		result.Confidence = "high"
		result.HasNAT = boolPtr(true)
		result.Description = localize(lang,
			"ICE 连接成功，但选中的最终路径为 TURN relay",
			"ICE connected successfully, but the selected path uses TURN relay",
		)
		return result
	case relayAvailable && !directAvailable:
		result.TypeCode = "udp_restricted"
		result.TypeName = "UDP Restricted / Relay Required"
		result.TypeNameZH = "UDP 受限 / 依赖中继"
		result.ConnectionMode = "relay"
		result.Confidence = "medium"
		result.HasNAT = boolPtr(true)
		result.Description = localize(lang,
			"收集到了 relay 候选，但缺少可用直连候选，网络更接近 UDP 受限或必须依赖 TURN",
			"Relay candidates were gathered without usable direct candidates, suggesting UDP restriction or TURN dependency",
		)
		return result
	case relayAvailable && directAvailable && !connected:
		result.TypeCode = "udp_restricted"
		result.TypeName = "UDP Restricted / Relay Preferred"
		result.TypeNameZH = "UDP 受限 / 倾向中继"
		result.ConnectionMode = "unknown"
		result.Confidence = "medium"
		result.HasNAT = boolPtr(true)
		result.Description = localize(lang,
			"存在 TURN relay 候选，但直连检查未成功，网络可能限制了 UDP 打洞",
			"TURN relay candidates are available, but direct ICE checks did not succeed; the network may restrict UDP hole punching",
		)
		return result
	case directAvailable:
		result.TypeCode = "direct_candidate_only"
		result.TypeName = "Direct Candidate Available"
		result.TypeNameZH = "存在直连候选"
		result.ConnectionMode = "unknown"
		result.Confidence = "low"
		result.Description = localize(lang,
			"已收集到 host 或 srflx 候选，但未拿到足够的 ICE 连通结果来确认最终路径",
			"Host or srflx candidates were gathered, but there is not enough ICE connectivity data to confirm the final path",
		)
		return result
	default:
		return result
	}
}

func boolPtr(v bool) *bool {
	return &v
}

func firstUsableHostIP(candidates []model.ICECandidateInfo) string {
	for _, c := range candidates {
		if isUsableIP(c.Address) {
			return c.Address
		}
	}
	return ""
}

func firstCandidateIP(candidates []model.ICECandidateInfo) string {
	for _, c := range candidates {
		if strings.TrimSpace(c.Address) != "" {
			return c.Address
		}
	}
	return ""
}

func firstCandidatePort(candidates []model.ICECandidateInfo) int {
	for _, c := range candidates {
		if c.Port > 0 {
			return c.Port
		}
	}
	return 0
}

func detectLocalIP(hostCandidates []model.ICECandidateInfo, selected model.ICECandidateInfo) string {
	if strings.EqualFold(strings.TrimSpace(selected.Type), "host") && isUsableIP(selected.Address) {
		return selected.Address
	}
	if isUsableIP(selected.RelatedAddress) {
		return selected.RelatedAddress
	}
	return firstUsableHostIP(hostCandidates)
}

func detectPublicIP(srflxCandidates []model.ICECandidateInfo, selectedLocal model.ICECandidateInfo, selectedRemote model.ICECandidateInfo) string {
	if strings.EqualFold(strings.TrimSpace(selectedLocal.Type), "srflx") && isUsableIP(selectedLocal.Address) {
		return selectedLocal.Address
	}
	if strings.EqualFold(strings.TrimSpace(selectedRemote.Type), "srflx") && isUsableIP(selectedRemote.Address) {
		return selectedRemote.Address
	}
	return firstCandidateIP(srflxCandidates)
}

func detectPublicPort(srflxCandidates []model.ICECandidateInfo, selectedLocal model.ICECandidateInfo, selectedRemote model.ICECandidateInfo) int {
	if strings.EqualFold(strings.TrimSpace(selectedLocal.Type), "srflx") && selectedLocal.Port > 0 {
		return selectedLocal.Port
	}
	if strings.EqualFold(strings.TrimSpace(selectedRemote.Type), "srflx") && selectedRemote.Port > 0 {
		return selectedRemote.Port
	}
	return firstCandidatePort(srflxCandidates)
}

func isSymmetricNAT(srflx []model.ICECandidateInfo) bool {
	mappings := make(map[string]map[string]struct{})
	for _, c := range srflx {
		localAddr := strings.TrimSpace(c.RelatedAddress)
		if !isUsableIP(localAddr) || c.RelatedPort <= 0 || c.Port <= 0 {
			continue
		}

		key := localAddr + ":" + strconv.Itoa(c.RelatedPort)
		if _, ok := mappings[key]; !ok {
			mappings[key] = make(map[string]struct{})
		}
		mappings[key][c.Address+":"+strconv.Itoa(c.Port)] = struct{}{}
		if len(mappings[key]) > 1 {
			return true
		}
	}
	return false
}

func summarizeProbes(req model.BrowserNATReportRequest) []probeSummary {
	probes := make([]probeSummary, 0, len(req.Probes))
	for _, probe := range req.Probes {
		summary := probeSummary{
			Label:      strings.TrimSpace(probe.Label),
			Selected:   probe.SelectedLocalCandidate,
			Connection: strings.ToLower(strings.TrimSpace(probe.ConnectionState)),
		}
		for _, candidate := range probe.Candidates {
			switch strings.ToLower(strings.TrimSpace(candidate.Type)) {
			case "host":
				summary.HasHost = true
			case "srflx":
				summary.HasSrflx = true
				summary.Srflx = append(summary.Srflx, candidate)
			case "relay":
				summary.HasRelay = true
			}
		}
		probes = append(probes, summary)
	}
	return probes
}

func hasSrflxProbe(probes []probeSummary) bool {
	for _, probe := range probes {
		if probe.HasSrflx {
			return true
		}
	}
	return false
}

func isSymmetricAcrossProbes(probes []probeSummary) bool {
	mappings := make(map[string]map[string]struct{})
	for _, probe := range probes {
		for _, c := range probe.Srflx {
			localAddr := strings.TrimSpace(c.RelatedAddress)
			if !isUsableIP(localAddr) || c.RelatedPort <= 0 || !isUsableIP(c.Address) || c.Port <= 0 {
				continue
			}
			key := localAddr + ":" + strconv.Itoa(c.RelatedPort)
			if _, ok := mappings[key]; !ok {
				mappings[key] = make(map[string]struct{})
			}
			mappings[key][c.Address+":"+strconv.Itoa(c.Port)] = struct{}{}
			if len(mappings[key]) > 1 {
				return true
			}
		}
	}
	return false
}

func isConsistentMappingAcrossProbes(probes []probeSummary) bool {
	mappings := make(map[string]string)
	matched := 0
	for _, probe := range probes {
		for _, c := range probe.Srflx {
			localAddr := strings.TrimSpace(c.RelatedAddress)
			if !isUsableIP(localAddr) || c.RelatedPort <= 0 || !isUsableIP(c.Address) || c.Port <= 0 {
				continue
			}
			matched++
			key := localAddr + ":" + strconv.Itoa(c.RelatedPort)
			mapped := c.Address + ":" + strconv.Itoa(c.Port)
			if existing, ok := mappings[key]; ok {
				if existing != mapped {
					return false
				}
				continue
			}
			mappings[key] = mapped
		}
	}
	return matched > 0
}

func hasMultipleSrflxMappingsInSingleProbe(probes []probeSummary) bool {
	for _, probe := range probes {
		mappings := make(map[string]struct{})
		for _, c := range probe.Srflx {
			if !isUsableIP(c.Address) || c.Port <= 0 {
				continue
			}
			mappings[c.Address+":"+strconv.Itoa(c.Port)] = struct{}{}
		}
		if len(mappings) > 1 {
			return true
		}
	}
	return false
}

func hasNAT(srflx []model.ICECandidateInfo) bool {
	for _, c := range srflx {
		if isUsableIP(c.Address) {
			return true
		}
	}
	return false
}

func hasPublicHostCandidate(host []model.ICECandidateInfo) bool {
	for _, c := range host {
		if isPublicIP(c.Address) {
			return true
		}
	}
	return false
}

func hasUsableHostCandidate(host []model.ICECandidateInfo) bool {
	for _, c := range host {
		if isUsableIP(c.Address) {
			return true
		}
	}
	return false
}

func hasPrivateHostCandidate(host []model.ICECandidateInfo) bool {
	for _, c := range host {
		if isPrivateIP(c.Address) {
			return true
		}
	}
	return false
}

func hasMaskedHostCandidate(host []model.ICECandidateInfo) bool {
	for _, c := range host {
		if strings.HasSuffix(strings.ToLower(strings.TrimSpace(c.Address)), ".local") {
			return true
		}
	}
	return false
}

func isUsableIP(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" || strings.HasSuffix(strings.ToLower(v), ".local") {
		return false
	}
	return net.ParseIP(v) != nil
}

func isPrivateIP(v string) bool {
	ip := net.ParseIP(strings.TrimSpace(v))
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

func isPublicIP(v string) bool {
	ip := net.ParseIP(strings.TrimSpace(v))
	if ip == nil {
		return false
	}
	return !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsUnspecified()
}

func isConnectedState(v string) bool {
	return v == "connected" || v == "completed"
}
