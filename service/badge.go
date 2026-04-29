package service

import "strings"

func ResolveUsageType(asUsageType, usageType string) string {
	if strings.TrimSpace(asUsageType) != "" {
		return strings.TrimSpace(asUsageType)
	}
	return strings.TrimSpace(usageType)
}

func BuildIPTypeBadge(raw string, isMobile bool, isHosting bool, isDatacenter bool, lang string) (string, string) {
	t := strings.ToLower(strings.TrimSpace(raw))

	switch t {
	case "residential":
		return "residential", localize(lang, "住宅", "Residential")
	case "mobile":
		return "mobile", localize(lang, "移动", "Mobile")
	case "datacenter":
		return "datacenter", localize(lang, "数据中心", "Data Center")
	case "business":
		return "business", localize(lang, "企业", "Business")
	case "education":
		return "education", localize(lang, "教育", "Education")
	case "government":
		return "government", localize(lang, "政府", "Government")
	case "hosting":
		return "hosting", localize(lang, "托管", "Hosting")
	case "cdn":
		return "cdn", localize(lang, "CDN", "CDN")
	case "isp":
		return "isp", localize(lang, "运营商网络", "ISP")
	}

	if isMobile {
		return "mobile", localize(lang, "移动", "Mobile")
	}
	if isDatacenter {
		return "datacenter", localize(lang, "数据中心", "Data Center")
	}
	if isHosting {
		return "hosting", localize(lang, "托管", "Hosting")
	}

	return "unknown", localize(lang, "未知", "Unknown")
}

func localize(lang, zh, en string) string {
	switch strings.ToLower(lang) {
	case "en", "en-us":
		return en
	default:
		return zh
	}
}