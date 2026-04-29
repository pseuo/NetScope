package service

import "ip-query/model"

func DefaultNATInfo(lang string) model.NATInfo {
	desc := "NAT 类型需要浏览器通过 WebRTC/STUN 主动检测"
	if lang == "en" {
		desc = "NAT type requires active browser-side WebRTC/STUN detection"
	}

	return model.NATInfo{
		Detected:       false,
		TypeCode:       "unknown",
		TypeName:       "Unknown",
		TypeNameZH:     "未知",
		Confidence:     "low",
		Method:         "none",
		Description:    desc,
		ConnectionMode: "unknown",
	}
}
