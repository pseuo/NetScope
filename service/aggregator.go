package service

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"ip-query/model"
	"ip-query/provider"
)

type Aggregator struct {
	MaxMind     *provider.MaxMindProvider
	DBIP        *provider.DBIPProvider
	IP2Location *provider.IP2LocationProvider
	IPInfo      *provider.IPInfoProvider
	IPAPI       *provider.IPAPIProvider
	IPData      *provider.IPDataProvider
	IPDataCloud *provider.IPDataCloudProvider
	IPing       *provider.IPingProvider
	IP9         *provider.IP9Provider
	ProxyCheck  *provider.ProxyCheckProvider
	Timeout     time.Duration
	DNSTimeout  time.Duration
	RDNSTimeout time.Duration
}

type queryResults struct {
	maxmind     *provider.MaxMindResult
	dbip        *provider.DBIPResult
	ip2location *provider.IP2LocationResult
	ipinfo      *provider.IPInfoResult
	ipapi       *provider.IPAPIResult
	ipdata      *provider.IPDataResult
	ipDataCloud *provider.IPDataCloudResult
	iping       *provider.IPingResult
	ip9         *provider.IP9Result
	proxyCheck  *provider.ProxyCheckResult
}

func NewAggregator(
	maxmind *provider.MaxMindProvider,
	dbip *provider.DBIPProvider,
	ip2 *provider.IP2LocationProvider,
	ipinfo *provider.IPInfoProvider,
	ipapi *provider.IPAPIProvider,
	ipdata *provider.IPDataProvider,
	ipdc *provider.IPDataCloudProvider,
	iping *provider.IPingProvider,
	ip9 *provider.IP9Provider,
	proxycheck *provider.ProxyCheckProvider,
) *Aggregator {
	return NewAggregatorWithTimeouts(maxmind, dbip, ip2, ipinfo, ipapi, ipdata, ipdc, iping, ip9, proxycheck, 10*time.Second, 1500*time.Millisecond, 1500*time.Millisecond)
}

func NewAggregatorWithTimeouts(
	maxmind *provider.MaxMindProvider,
	dbip *provider.DBIPProvider,
	ip2 *provider.IP2LocationProvider,
	ipinfo *provider.IPInfoProvider,
	ipapi *provider.IPAPIProvider,
	ipdata *provider.IPDataProvider,
	ipdc *provider.IPDataCloudProvider,
	iping *provider.IPingProvider,
	ip9 *provider.IP9Provider,
	proxycheck *provider.ProxyCheckProvider,
	timeout time.Duration,
	dnsTimeout time.Duration,
	rdnsTimeout time.Duration,
) *Aggregator {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if dnsTimeout <= 0 {
		dnsTimeout = 1500 * time.Millisecond
	}
	if rdnsTimeout <= 0 {
		rdnsTimeout = 1500 * time.Millisecond
	}
	return &Aggregator{
		MaxMind:     maxmind,
		DBIP:        dbip,
		IP2Location: ip2,
		IPInfo:      ipinfo,
		IPAPI:       ipapi,
		IPData:      ipdata,
		IPDataCloud: ipdc,
		IPing:       iping,
		IP9:         ip9,
		ProxyCheck:  proxycheck,
		Timeout:     timeout,
		DNSTimeout:  dnsTimeout,
		RDNSTimeout: rdnsTimeout,
	}
}

func (a *Aggregator) Query(input string, lang string) (*model.QueryResponse, error) {
	queryType := "ip"
	targetIP := input

	var ipv4List, ipv6List []string

	if !IsIP(input) {
		queryType = "domain"
		v4, v6, err := ResolveDomainIPsTimeout(input, a.DNSTimeout)
		if err != nil {
			return nil, err
		}
		ipv4List = v4
		ipv6List = v6

		if len(ipv4List) > 0 {
			targetIP = ipv4List[0]
		} else if len(ipv6List) > 0 {
			targetIP = ipv6List[0]
		} else {
			return nil, fmt.Errorf("no A/AAAA record found")
		}
	}

	if net.ParseIP(targetIP) == nil {
		return nil, fmt.Errorf("invalid ip")
	}

	resp := &model.QueryResponse{
		Address: model.AddressInfo{
			Query:     input,
			QueryType: queryType,
			IP:        targetIP,
			IPVersion: DetectIPVersion(targetIP),
			IPv4List:  ipv4List,
			IPv6List:  ipv6List,
		},
		NAT: DefaultNATInfo(lang),
	}

	results := &queryResults{}
	var mu sync.Mutex

	var wg sync.WaitGroup
	wg.Add(10)

	go func() {
		defer wg.Done()
		if a.MaxMind != nil {
			result, _ := a.MaxMind.Query(targetIP)
			mu.Lock()
			results.maxmind = result
			mu.Unlock()
		}
	}()

	go func() {
		defer wg.Done()
		if a.DBIP != nil {
			result, _ := a.DBIP.Query(targetIP)
			mu.Lock()
			results.dbip = result
			mu.Unlock()
		}
	}()

	go func() {
		defer wg.Done()
		if a.IP2Location != nil {
			result, _ := a.IP2Location.Query(targetIP)
			mu.Lock()
			results.ip2location = result
			mu.Unlock()
		}
	}()

	go func() {
		defer wg.Done()
		if a.IPInfo != nil {
			result, _ := a.IPInfo.Query(targetIP)
			mu.Lock()
			results.ipinfo = result
			mu.Unlock()
		}
	}()

	go func() {
		defer wg.Done()
		if a.IPAPI != nil {
			result, _ := a.IPAPI.Query(targetIP)
			mu.Lock()
			results.ipapi = result
			mu.Unlock()
		}
	}()

	go func() {
		defer wg.Done()
		if a.IPData != nil {
			result, _ := a.IPData.Query(targetIP)
			mu.Lock()
			results.ipdata = result
			mu.Unlock()
		}
	}()

	go func() {
		defer wg.Done()
		if a.IPDataCloud != nil {
			result, _ := a.IPDataCloud.Query(targetIP)
			mu.Lock()
			results.ipDataCloud = result
			mu.Unlock()
		}
	}()

	go func() {
		defer wg.Done()
		if a.IPing != nil {
			result, _ := a.IPing.Query(targetIP)
			mu.Lock()
			results.iping = result
			mu.Unlock()
		}
	}()

	go func() {
		defer wg.Done()
		if a.IP9 != nil {
			result, _ := a.IP9.Query(targetIP)
			mu.Lock()
			results.ip9 = result
			mu.Unlock()
		}
	}()

	go func() {
		defer wg.Done()
		if a.ProxyCheck != nil {
			result, _ := a.ProxyCheck.Query(targetIP)
			mu.Lock()
			results.proxyCheck = result
			mu.Unlock()
		}
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(a.Timeout):
	}

	mu.Lock()
	mm := results.maxmind
	dbip := results.dbip
	ip2 := results.ip2location
	ipinfo := results.ipinfo
	ipa := results.ipapi
	ipdata := results.ipdata
	ipdc := results.ipDataCloud
	iping := results.iping
	ip9 := results.ip9
	pcx := results.proxyCheck
	mu.Unlock()

	if ip2 != nil && ip2.Hostname != "" {
		resp.Address.Hostname = ip2.Hostname
	} else if ipinfo != nil && ipinfo.Hostname != "" {
		resp.Address.Hostname = ipinfo.Hostname
	} else if ipa != nil && ipa.Reverse != "" {
		resp.Address.Hostname = ipa.Reverse
	} else {
		resp.Address.Hostname = ReverseLookupTimeout(targetIP, a.RDNSTimeout)
	}

	fillNetworkInfo(resp, mm, dbip, ip2, ipinfo, ipa, ipdata, ipdc, iping, ip9, pcx)
	fillLocationInfo(resp, mm, dbip, ip2, ipinfo, ipa, ipdata, ipdc, iping, ip9, pcx)
	fillSecurityInfo(resp, ip2, ipa, ipdata, iping, pcx)

	asUsageType := ""
	usageType := ""
	if ip2 != nil {
		asUsageType = ip2.ASUsageType
		usageType = ip2.UsageType
	}

	rawUsageType := ResolveUsageType(asUsageType, usageType)
	if rawUsageType == "" && ip9 != nil {
		switch strings.ToUpper(strings.TrimSpace(ip9.IPType)) {
		case "ISP":
			rawUsageType = "isp"
		case "BUS":
			rawUsageType = "business"
		case "IDC":
			rawUsageType = "datacenter"
			resp.Security.IsDatacenter = true
			if resp.Source.DatacenterSource == "" {
				resp.Source.DatacenterSource = "ip9"
			}
		}
		if rawUsageType != "" && resp.Source.TypeSource == "" {
			resp.Source.TypeSource = "ip9"
		}
	}
	if rawUsageType == "" && pcx != nil {
		switch {
		case strings.Contains(strings.ToLower(pcx.Type), "wireless"), strings.Contains(strings.ToLower(pcx.Type), "mobile"):
			rawUsageType = "mobile"
		case strings.Contains(strings.ToLower(pcx.Type), "hosting"), strings.Contains(strings.ToLower(pcx.Type), "datacenter"):
			rawUsageType = "hosting"
		}
	}
	if rawUsageType == "" && iping != nil {
		switch strings.ToUpper(strings.TrimSpace(iping.UsageType)) {
		case "ISP":
			rawUsageType = "isp"
		case "BUS", "BUSINESS", "COM":
			rawUsageType = "business"
		case "IDC", "HOSTING", "DATACENTER", "DATA CENTER":
			rawUsageType = "datacenter"
			resp.Security.IsDatacenter = true
			if resp.Source.DatacenterSource == "" {
				resp.Source.DatacenterSource = "iping"
			}
		}
		if rawUsageType != "" && resp.Source.TypeSource == "" {
			resp.Source.TypeSource = "iping"
		}
	}
	if rawUsageType == "" {
		fallbackUsageType := inferUsageTypeFromNetwork(resp.Network.ISP, resp.Network.ASNOrganization)
		if fallbackUsageType != "" {
			rawUsageType = fallbackUsageType
			if rawUsageType == "mobile" && !resp.Security.IsMobile {
				resp.Security.IsMobile = true
				if resp.Source.MobileSource == "" {
					resp.Source.MobileSource = "network-inference"
				}
			}
			if (rawUsageType == "hosting" || rawUsageType == "datacenter") && !resp.Security.IsHosting {
				resp.Security.IsHosting = true
				if resp.Source.HostingSource == "" {
					resp.Source.HostingSource = "network-inference"
				}
			}
		}
	}
	code, label := BuildIPTypeBadge(
		rawUsageType,
		resp.Security.IsMobile,
		resp.Security.IsHosting,
		resp.Security.IsDatacenter,
		lang,
	)

	resp.IPType = model.IPTypeBadge{
		Code:         code,
		Label:        label,
		RawUsageType: rawUsageType,
	}

	log.Printf("aggregator result: ip=%s geo=%s isp=%s asn=%s security=%s dbip=%t ipinfo=%t ipdata=%t ipdc=%t iping=%t ip9=%t pcx=%t",
		targetIP,
		resp.Source.GeoSource,
		resp.Source.ISPSource,
		resp.Source.ASNSource,
		resp.Source.SecuritySource,
		dbip != nil,
		ipinfo != nil,
		ipdata != nil,
		ipdc != nil,
		iping != nil,
		ip9 != nil,
		pcx != nil,
	)

	return resp, nil
}

func fillNetworkInfo(
	resp *model.QueryResponse,
	mm *provider.MaxMindResult,
	dbip *provider.DBIPResult,
	ip2 *provider.IP2LocationResult,
	ipinfo *provider.IPInfoResult,
	ipa *provider.IPAPIResult,
	ipdata *provider.IPDataResult,
	ipdc *provider.IPDataCloudResult,
	iping *provider.IPingResult,
	ip9 *provider.IP9Result,
	pcx *provider.ProxyCheckResult,
) {
	if mm != nil && mm.ASN > 0 {
		resp.Network.ASNNumber = mm.ASN
		resp.Network.ASN = fmt.Sprintf("AS%d", mm.ASN)
		resp.Network.ASNOrganization = mm.ASNOrganization
		resp.Source.ASNSource = "maxmind"
	}

	if dbip != nil && resp.Network.ASN == "" && dbip.ASN > 0 {
		resp.Network.ASNNumber = dbip.ASN
		resp.Network.ASN = fmt.Sprintf("AS%d", dbip.ASN)
		resp.Network.ASNOrganization = dbip.ASNOrganization
		resp.Source.ASNSource = "db-ip"
	}

	if ip2 != nil {
		if resp.Network.ISP == "" && ip2.ISP != "" {
			resp.Network.ISP = ip2.ISP
			resp.Source.ISPSource = "ip2location"
		}
		if resp.Network.IPOrganization == "" && ip2.Organization != "" {
			resp.Network.IPOrganization = ip2.Organization
		}
		if resp.Network.ASN == "" && ip2.ASN != "" {
			asnText := normalizeASN(ip2.ASN)
			resp.Network.ASN = asnText
			resp.Network.ASNNumber = parseASNNumber(asnText)
			resp.Source.ASNSource = "ip2location"
		}
		if resp.Network.ASNOrganization == "" && ip2.AS != "" {
			resp.Network.ASNOrganization = ip2.AS
		}
	}

	if ipinfo != nil {
		if resp.Network.IPOrganization == "" && ipinfo.Org != "" {
			resp.Network.IPOrganization = ipinfo.Org
		}
		if resp.Network.ASN == "" && ipinfo.ASN != "" {
			resp.Network.ASN = ipinfo.ASN
			resp.Network.ASNNumber = ipinfo.ASNNumber
			resp.Source.ASNSource = "ipinfo"
		}
		if resp.Network.ASNOrganization == "" && ipinfo.ASNOrganization != "" {
			resp.Network.ASNOrganization = ipinfo.ASNOrganization
		}
	}

	if ipa != nil {
		if resp.Network.ISP == "" && ipa.ISP != "" {
			resp.Network.ISP = ipa.ISP
			resp.Source.ISPSource = "ip-api"
		}
		if resp.Network.IPOrganization == "" && ipa.Org != "" {
			resp.Network.IPOrganization = ipa.Org
		}
		if resp.Network.ASN == "" && ipa.AS != "" {
			resp.Network.ASN = extractASNumber(ipa.AS)
			resp.Network.ASNNumber = parseASNNumber(resp.Network.ASN)
			resp.Network.ASNOrganization = extractASOrg(ipa.AS)
			resp.Source.ASNSource = "ip-api"
		}
	}

	if ipdata != nil {
		if resp.Network.ISP == "" && ipdata.Carrier.Name != "" {
			resp.Network.ISP = ipdata.Carrier.Name
			resp.Source.ISPSource = "ipdata"
		}
		if resp.Network.IPOrganization == "" && ipdata.ASN.Name != "" {
			resp.Network.IPOrganization = ipdata.ASN.Name
		}
		if resp.Network.ASN == "" && ipdata.NormalizedASN() != "" {
			resp.Network.ASN = ipdata.NormalizedASN()
			resp.Network.ASNNumber = parseASNNumber(resp.Network.ASN)
			resp.Source.ASNSource = "ipdata"
		}
		if resp.Network.ASNOrganization == "" && ipdata.ASN.Name != "" {
			resp.Network.ASNOrganization = ipdata.ASN.Name
		}
	}

	if ipdc != nil {
		if resp.Network.ISP == "" && ipdc.ISP != "" {
			resp.Network.ISP = ipdc.ISP
			resp.Source.ISPSource = "ipdatacloud"
		}
	}

	if iping != nil {
		if resp.Network.ISP == "" && iping.ISP != "" {
			resp.Network.ISP = iping.ISP
			resp.Source.ISPSource = "iping"
		}
		if resp.Network.IPOrganization == "" && iping.Company != "" {
			resp.Network.IPOrganization = iping.Company
		}
		if resp.Network.Company == "" && iping.Company != "" {
			resp.Network.Company = iping.Company
		}
		if resp.Network.CompanyDomain == "" && iping.CompanyDomain != "" {
			resp.Network.CompanyDomain = iping.CompanyDomain
		}
		if resp.Network.CompanyType == "" && iping.CompanyType != "" {
			resp.Network.CompanyType = iping.CompanyType
		}
		if resp.Network.CompanyCountry == "" && iping.CompanyCountry != "" {
			resp.Network.CompanyCountry = iping.CompanyCountry
		}
		if resp.Network.ASN == "" && iping.ASN != "" {
			resp.Network.ASN = normalizeASN(iping.ASN)
			resp.Network.ASNNumber = parseASNNumber(resp.Network.ASN)
			resp.Source.ASNSource = "iping"
		}
		if resp.Network.ASNOrganization == "" && iping.ASNOwner != "" {
			resp.Network.ASNOrganization = iping.ASNOwner
		}
		if resp.Network.ASNType == "" && iping.ASNType != "" {
			resp.Network.ASNType = iping.ASNType
		}
		if resp.Network.ASNDomain == "" && iping.ASNDomain != "" {
			resp.Network.ASNDomain = iping.ASNDomain
		}
		if resp.Network.ASNCountry == "" && iping.ASNCountry != "" {
			resp.Network.ASNCountry = iping.ASNCountry
		}
	}

	if ip9 != nil {
		if resp.Network.ISP == "" && ip9.ISP != "" {
			resp.Network.ISP = ip9.ISP
			resp.Source.ISPSource = "ip9"
		}
	}

	if pcx != nil {
		if resp.Network.ISP == "" && pcx.Provider != "" {
			resp.Network.ISP = pcx.Provider
			resp.Source.ISPSource = "proxycheck"
		}
		if resp.Network.ASN == "" && pcx.ASN != "" {
			resp.Network.ASN = normalizeASN(pcx.ASN)
			resp.Network.ASNNumber = parseASNNumber(resp.Network.ASN)
			resp.Source.ASNSource = "proxycheck"
		}
		if resp.Network.ASNOrganization == "" && pcx.Provider != "" {
			resp.Network.ASNOrganization = pcx.Provider
		}
		if resp.Network.IPOrganization == "" && pcx.Organisation != "" {
			resp.Network.IPOrganization = pcx.Organisation
		}
	}
}

func fillLocationInfo(
	resp *model.QueryResponse,
	mm *provider.MaxMindResult,
	dbip *provider.DBIPResult,
	ip2 *provider.IP2LocationResult,
	ipinfo *provider.IPInfoResult,
	ipa *provider.IPAPIResult,
	ipdata *provider.IPDataResult,
	ipdc *provider.IPDataCloudResult,
	iping *provider.IPingResult,
	ip9 *provider.IP9Result,
	pcx *provider.ProxyCheckResult,
) {
	if mm != nil {
		resp.Location.Country = mm.Country
		resp.Location.CountryCode = mm.CountryCode
		resp.Location.Region = mm.Region
		resp.Location.Province = mm.Region
		resp.Location.City = mm.City
		resp.Location.PostalCode = mm.PostalCode
		resp.Location.Timezone = mm.Timezone
		resp.Location.Latitude = mm.Latitude
		resp.Location.Longitude = mm.Longitude
		resp.Source.GeoSource = "maxmind"
	}

	if dbip != nil && resp.Location.Country == "" {
		resp.Location.Country = dbip.Country
		resp.Location.CountryCode = dbip.CountryCode
		resp.Location.Region = dbip.Region
		resp.Location.Province = dbip.Region
		resp.Location.City = dbip.City
		resp.Location.PostalCode = dbip.PostalCode
		resp.Location.Timezone = dbip.Timezone
		resp.Location.Latitude = dbip.Latitude
		resp.Location.Longitude = dbip.Longitude
		resp.Source.GeoSource = "db-ip"
	}

	if ip2 != nil && resp.Location.Country == "" {
		resp.Location.Country = ip2.Country
		resp.Location.CountryCode = ip2.CountryCode
		resp.Location.Region = ip2.Region
		resp.Location.Province = ip2.Region
		resp.Location.City = ip2.City
		resp.Location.PostalCode = ip2.ZipCode
		resp.Location.Timezone = ip2.TimeZone
		resp.Location.Latitude = ip2.Latitude
		resp.Location.Longitude = ip2.Longitude
		resp.Source.GeoSource = "ip2location"
	}

	if ipinfo != nil && resp.Location.Country == "" {
		resp.Location.CountryCode = ipinfo.CountryCode
		resp.Location.Region = ipinfo.Region
		resp.Location.Province = ipinfo.Region
		resp.Location.City = ipinfo.City
		resp.Location.PostalCode = ipinfo.PostalCode
		resp.Location.Timezone = ipinfo.Timezone
		resp.Location.Latitude = ipinfo.Latitude
		resp.Location.Longitude = ipinfo.Longitude
		resp.Source.GeoSource = "ipinfo"
	}

	if ipa != nil && resp.Location.Country == "" {
		resp.Location.Country = ipa.Country
		resp.Location.CountryCode = ipa.CountryCode
		resp.Location.Region = ipa.RegionName
		resp.Location.Province = ipa.RegionName
		resp.Location.City = ipa.City
		resp.Location.PostalCode = ipa.Zip
		resp.Location.Timezone = ipa.Timezone
		resp.Location.Latitude = ipa.Lat
		resp.Location.Longitude = ipa.Lon
		resp.Source.GeoSource = "ip-api"
	}

	if ipdata != nil {
		if resp.Location.Continent == "" && ipdata.Continent != "" {
			resp.Location.Continent = ipdata.Continent
		}
		if resp.Location.Country == "" && ipdata.Country != "" {
			resp.Location.Country = ipdata.Country
			resp.Source.GeoSource = "ipdata"
		}
		if resp.Location.CountryCode == "" && ipdata.CountryCode != "" {
			resp.Location.CountryCode = ipdata.CountryCode
		}
		if resp.Location.Region == "" && ipdata.Region != "" {
			resp.Location.Region = ipdata.Region
		}
		if resp.Location.Province == "" && ipdata.Region != "" {
			resp.Location.Province = ipdata.Region
		}
		if resp.Location.City == "" && ipdata.City != "" {
			resp.Location.City = ipdata.City
		}
		if resp.Location.PostalCode == "" && ipdata.PostalCode != "" {
			resp.Location.PostalCode = ipdata.PostalCode
		}
		if resp.Location.Timezone == "" && ipdata.Timezone.Name != "" {
			resp.Location.Timezone = ipdata.Timezone.Name
		}
		if resp.Location.Latitude == 0 && ipdata.Latitude != 0 {
			resp.Location.Latitude = ipdata.Latitude
		}
		if resp.Location.Longitude == 0 && ipdata.Longitude != 0 {
			resp.Location.Longitude = ipdata.Longitude
		}
	}

	if ipdc != nil {
		if resp.Location.Continent == "" && ipdc.Continent != "" {
			resp.Location.Continent = ipdc.Continent
		}
		if resp.Location.Country == "" && ipdc.Country != "" {
			resp.Location.Country = ipdc.Country
			resp.Source.GeoSource = "ipdatacloud"
		}
		if resp.Location.CountryCode == "" && ipdc.CountryCode != "" {
			resp.Location.CountryCode = ipdc.CountryCode
		}
		if resp.Location.Region == "" && ipdc.Province != "" {
			resp.Location.Region = ipdc.Province
		}
		if resp.Location.Province == "" && ipdc.Province != "" {
			resp.Location.Province = ipdc.Province
		}
		if resp.Location.City == "" && ipdc.City != "" {
			resp.Location.City = ipdc.City
		}
		if resp.Location.District == "" && ipdc.District != "" {
			resp.Location.District = ipdc.District
		}
		if resp.Location.Street == "" && ipdc.Street != "" {
			resp.Location.Street = ipdc.Street
		}
		if resp.Location.Radius == "" && ipdc.Radius != "" {
			resp.Location.Radius = ipdc.Radius
		}
		if resp.Location.AreaCode == "" && ipdc.AreaCode != "" {
			resp.Location.AreaCode = ipdc.AreaCode
		}
		if resp.Location.PostalCode == "" && ipdc.ZipCode != "" {
			resp.Location.PostalCode = ipdc.ZipCode
		}
		if resp.Location.CityCode == "" && ipdc.CityCode != "" {
			resp.Location.CityCode = ipdc.CityCode
		}
		if resp.Location.Timezone == "" && ipdc.TimeZone != "" {
			resp.Location.Timezone = ipdc.TimeZone
		}
		if resp.Location.Elevation == "" && ipdc.Elevation != "" {
			resp.Location.Elevation = ipdc.Elevation
		}
		if resp.Location.WeatherStation == "" && ipdc.WeatherStation != "" {
			resp.Location.WeatherStation = ipdc.WeatherStation
		}
		if resp.Location.Latitude == 0 && ipdc.Latitude != 0 {
			resp.Location.Latitude = ipdc.Latitude
		}
		if resp.Location.Longitude == 0 && ipdc.Longitude != 0 {
			resp.Location.Longitude = ipdc.Longitude
		}
	}

	if iping != nil {
		if resp.Location.Continent == "" && iping.Continent != "" {
			resp.Location.Continent = iping.Continent
		}
		if resp.Location.Country == "" && iping.Country != "" {
			resp.Location.Country = iping.Country
			resp.Source.GeoSource = "iping"
		}
		if resp.Location.Region == "" && iping.Region != "" {
			resp.Location.Region = iping.Region
		}
		if resp.Location.Province == "" && iping.Region != "" {
			resp.Location.Province = iping.Region
		}
		if resp.Location.City == "" && iping.City != "" {
			resp.Location.City = iping.City
		}
		if resp.Location.Latitude == 0 && iping.Latitude != 0 {
			resp.Location.Latitude = iping.Latitude
		}
		if resp.Location.Longitude == 0 && iping.Longitude != 0 {
			resp.Location.Longitude = iping.Longitude
		}
	}

	if ip9 != nil {
		if resp.Location.Country == "" && ip9.Country != "" {
			resp.Location.Country = ip9.Country
			resp.Source.GeoSource = "ip9"
		}
		if resp.Location.CountryCode == "" && ip9.CountryCode != "" {
			resp.Location.CountryCode = ip9.CountryCode
		}
		if resp.Location.Region == "" && ip9.Province != "" {
			resp.Location.Region = ip9.Province
		}
		if resp.Location.Province == "" && ip9.Province != "" {
			resp.Location.Province = ip9.Province
		}
		if resp.Location.City == "" && ip9.City != "" {
			resp.Location.City = ip9.City
		}
		if resp.Location.District == "" && ip9.Area != "" {
			resp.Location.District = ip9.Area
		}
		if resp.Location.AreaCode == "" && ip9.AreaCode != "" {
			resp.Location.AreaCode = ip9.AreaCode
		}
		if resp.Location.PostalCode == "" && ip9.PostCode != "" {
			resp.Location.PostalCode = ip9.PostCode
		}
		if resp.Location.CityCode == "" && ip9.CityCode != "" {
			resp.Location.CityCode = ip9.CityCode
		}
		if resp.Location.Latitude == 0 && ip9.Latitude != 0 {
			resp.Location.Latitude = ip9.Latitude
		}
		if resp.Location.Longitude == 0 && ip9.Longitude != 0 {
			resp.Location.Longitude = ip9.Longitude
		}
	}

	if pcx != nil {
		if resp.Location.Country == "" && pcx.Country != "" {
			resp.Location.Country = pcx.Country
			resp.Source.GeoSource = "proxycheck"
		}
		if resp.Location.City == "" && pcx.City != "" {
			resp.Location.City = pcx.City
		}
	}

	resp.Location.Formatted = formatLocationFull(
		resp.Location.Country,
		resp.Location.Province,
		resp.Location.City,
		resp.Location.District,
		resp.Location.Street,
	)
}

func fillSecurityInfo(
	resp *model.QueryResponse,
	ip2 *provider.IP2LocationResult,
	ipa *provider.IPAPIResult,
	ipdata *provider.IPDataResult,
	iping *provider.IPingResult,
	pcx *provider.ProxyCheckResult,
) {
	if ip2 != nil {
		if ip2.Proxy {
			resp.Security.IsProxy = true
			resp.Source.ProxySource = "ip2location"
		}
		if ip2.VPN {
			resp.Security.IsVPN = true
			resp.Source.VPNSource = "ip2location"
		}
		if ip2.Tor {
			resp.Security.IsTor = true
			resp.Source.TorSource = "ip2location"
		}
		if ip2.Datacenter {
			resp.Security.IsDatacenter = true
			resp.Source.DatacenterSource = "ip2location"
		}

		if ip2.Proxy || ip2.VPN || ip2.Tor || ip2.Datacenter {
			resp.Source.SecuritySource = "ip2location"
		}
	}

	if ipa != nil {
		if !resp.Security.IsProxy && ipa.Proxy {
			resp.Security.IsProxy = true
			resp.Source.ProxySource = "ip-api"
		}
		if !resp.Security.IsHosting && ipa.Hosting {
			resp.Security.IsHosting = true
			resp.Source.HostingSource = "ip-api"
		}
		if !resp.Security.IsMobile && ipa.Mobile {
			resp.Security.IsMobile = true
			resp.Source.MobileSource = "ip-api"
		}

		if resp.Source.SecuritySource == "" && (ipa.Proxy || ipa.Hosting || ipa.Mobile) {
			resp.Source.SecuritySource = "ip-api"
		}
	}

	if ipdata != nil {
		changed := false
		if !resp.Security.IsProxy && (ipdata.Threat.IsProxy || ipdata.Threat.IsAnonymous) {
			resp.Security.IsProxy = true
			resp.Source.ProxySource = "ipdata"
			changed = true
		}
		if !resp.Security.IsTor && ipdata.Threat.IsTor {
			resp.Security.IsTor = true
			resp.Source.TorSource = "ipdata"
			changed = true
		}
		asnType := strings.ToLower(strings.TrimSpace(ipdata.ASN.Type))
		if !resp.Security.IsHosting && (strings.Contains(asnType, "hosting") || strings.Contains(asnType, "business")) {
			resp.Security.IsHosting = true
			resp.Source.HostingSource = "ipdata"
			changed = true
		}
		if !resp.Security.IsMobile && ipdata.Carrier.Name != "" {
			resp.Security.IsMobile = true
			resp.Source.MobileSource = "ipdata"
			changed = true
		}
		if resp.Security.Type == "" && ipdata.ASN.Type != "" {
			resp.Security.Type = ipdata.ASN.Type
			resp.Source.TypeSource = "ipdata"
			changed = true
		}
		if resp.Source.SecuritySource == "" && (changed || ipdata.Threat.IsThreat || ipdata.Threat.IsKnownAttacker || ipdata.Threat.IsKnownAbuser) {
			resp.Source.SecuritySource = "ipdata"
		}
	}

	if iping != nil {
		changed := false
		if !resp.Security.IsProxy && iping.IsProxy {
			resp.Security.IsProxy = true
			resp.Source.ProxySource = "iping"
			changed = true
		}
		usageType := strings.ToLower(strings.TrimSpace(iping.UsageType + " " + iping.ASNType + " " + iping.CompanyType))
		if !resp.Security.IsHosting && (strings.Contains(usageType, "idc") || strings.Contains(usageType, "hosting") || strings.Contains(usageType, "datacenter")) {
			resp.Security.IsHosting = true
			resp.Source.HostingSource = "iping"
			changed = true
		}
		if !resp.Security.IsDatacenter && (strings.Contains(usageType, "idc") || strings.Contains(usageType, "datacenter")) {
			resp.Security.IsDatacenter = true
			resp.Source.DatacenterSource = "iping"
			changed = true
		}
		if resp.Security.RiskScore == 0 && iping.RiskScore > 0 {
			resp.Security.RiskScore = iping.RiskScore
			resp.Source.RiskSource = "iping"
			changed = true
		}
		if resp.Security.RiskTag == "" && iping.RiskTag != "" {
			resp.Security.RiskTag = iping.RiskTag
			changed = true
		}
		if resp.Security.Type == "" && iping.Type != "" {
			resp.Security.Type = iping.Type
			resp.Source.TypeSource = "iping"
			changed = true
		}
		if resp.Source.SecuritySource == "" && changed {
			resp.Source.SecuritySource = "iping"
		}
	}

	if pcx != nil {
		changed := false

		if !resp.Security.IsProxy && pcx.Proxy {
			resp.Security.IsProxy = true
			resp.Source.ProxySource = "proxycheck"
			changed = true
		}
		if !resp.Security.IsVPN && pcx.VPN {
			resp.Security.IsVPN = true
			resp.Source.VPNSource = "proxycheck"
			changed = true
		}
		if !resp.Security.IsTor && pcx.Tor {
			resp.Security.IsTor = true
			resp.Source.TorSource = "proxycheck"
			changed = true
		}
		if !resp.Security.IsHosting && pcx.Hosting {
			resp.Security.IsHosting = true
			resp.Source.HostingSource = "proxycheck"
			changed = true
		}
		if !resp.Security.IsDatacenter && pcx.Datacenter {
			resp.Security.IsDatacenter = true
			resp.Source.DatacenterSource = "proxycheck"
			changed = true
		}

		if resp.Security.RiskScore == 0 && pcx.RiskScore > 0 {
			resp.Security.RiskScore = pcx.RiskScore
			resp.Source.RiskSource = "proxycheck"
			changed = true
		}
		if resp.Security.Type == "" && pcx.Type != "" {
			resp.Security.Type = pcx.Type
			resp.Source.TypeSource = "proxycheck"
			changed = true
		}
		pcxTypeLower := strings.ToLower(pcx.Type)
		if !resp.Security.IsMobile && (strings.Contains(pcxTypeLower, "wireless") || strings.Contains(pcxTypeLower, "mobile")) {
			resp.Security.IsMobile = true
			resp.Source.MobileSource = "proxycheck"
			changed = true
		}
		if resp.Security.Provider == "" && pcx.Provider != "" {
			resp.Security.Provider = pcx.Provider
		}

		if (resp.Source.SecuritySource == "" && (pcx.Proxy || pcx.VPN || pcx.Tor || pcx.Hosting || pcx.Datacenter)) || changed {
			resp.Source.SecuritySource = "proxycheck"
		}
	}

	if resp.Security.IsDatacenter {
		resp.Security.IsHosting = true
		if resp.Source.HostingSource == "" {
			resp.Source.HostingSource = resp.Source.DatacenterSource
		}
	}
}

func formatLocationFull(country, province, city, district, street string) string {
	var parts []string
	if country != "" {
		parts = append(parts, country)
	}
	if province != "" {
		parts = append(parts, province)
	}
	if city != "" {
		parts = append(parts, city)
	}
	if district != "" {
		parts = append(parts, district)
	}
	if street != "" {
		parts = append(parts, street)
	}
	return strings.Join(parts, " / ")
}

func inferUsageTypeFromNetwork(isp, asnOrg string) string {
	text := strings.ToLower(strings.TrimSpace(isp + " " + asnOrg))
	if text == "" {
		return ""
	}

	mobileKeywords := []string{
		"china mobile",
		"cmcc",
		"china unicom",
		"unicom",
		"cucc",
		"china telecom",
		"telecom",
		"ctcc",
		"china broadcasting network",
		"cbn",
		"wireless",
		"mobile",
		"中国移动",
		"移动",
		"中国联通",
		"联通",
		"中国电信",
		"电信",
		"中国广电",
		"广电",
	}
	for _, keyword := range mobileKeywords {
		if strings.Contains(text, keyword) {
			return "mobile"
		}
	}

	hostingKeywords := []string{
		"amazon",
		"aws",
		"google cloud",
		"microsoft",
		"azure",
		"aliyun",
		"alibaba cloud",
		"tencent cloud",
		"huawei cloud",
		"oracle cloud",
		"digitalocean",
		"linode",
		"vultr",
		"datacenter",
		"data center",
		"hosting",
		"cloud",
		"机房",
		"云计算",
		"云服务",
	}
	for _, keyword := range hostingKeywords {
		if strings.Contains(text, keyword) {
			return "hosting"
		}
	}

	businessKeywords := []string{
		"business",
		"enterprise",
		"corp",
		"company",
		"企业",
		"集团",
	}
	for _, keyword := range businessKeywords {
		if strings.Contains(text, keyword) {
			return "business"
		}
	}

	return ""
}
