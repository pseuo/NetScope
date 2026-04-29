package service

import (
	"regexp"
	"strconv"
	"strings"
)

var asnRegexp = regexp.MustCompile(`AS(\d+)`)

func normalizeASN(s string) string {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "AS") {
		return s
	}
	return "AS" + s
}

func parseASNNumber(asn string) uint {
	asn = strings.ToUpper(strings.TrimSpace(asn))
	asn = strings.TrimPrefix(asn, "AS")
	n, err := strconv.ParseUint(asn, 10, 32)
	if err != nil {
		return 0
	}
	return uint(n)
}

func extractASNumber(asField string) string {
	m := asnRegexp.FindStringSubmatch(strings.ToUpper(asField))
	if len(m) > 1 {
		return "AS" + m[1]
	}
	return ""
}

func extractASOrg(asField string) string {
	asField = strings.TrimSpace(asField)
	if asField == "" {
		return ""
	}
	parts := strings.SplitN(asField, " ", 2)
	if len(parts) == 2 {
		return strings.TrimSpace(parts[1])
	}
	return ""
}