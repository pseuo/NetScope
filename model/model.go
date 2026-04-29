package model

type QueryResponse struct {
	Address  AddressInfo  `json:"address"`
	Network  NetworkInfo  `json:"network"`
	Location LocationInfo `json:"location"`
	Security SecurityInfo `json:"security"`
	IPType   IPTypeBadge  `json:"ip_type"`
	NAT      NATInfo      `json:"nat"`
	Source   SourceInfo   `json:"source"`
}

type AddressInfo struct {
	Query     string   `json:"query"`
	QueryType string   `json:"query_type"`
	IP        string   `json:"ip"`
	IPVersion string   `json:"ip_version"`
	Hostname  string   `json:"hostname"`
	IPv4List  []string `json:"ipv4_list,omitempty"`
	IPv6List  []string `json:"ipv6_list,omitempty"`
}

type NetworkInfo struct {
	ISP             string `json:"isp"`
	IPOrganization  string `json:"ip_organization"`
	ASN             string `json:"asn"`
	ASNNumber       uint   `json:"asn_number"`
	ASNOrganization string `json:"asn_organization"`
	ASNType         string `json:"asn_type"`
	ASNDomain       string `json:"asn_domain"`
	ASNCountry      string `json:"asn_country"`
	Company         string `json:"company"`
	CompanyDomain   string `json:"company_domain"`
	CompanyType     string `json:"company_type"`
	CompanyCountry  string `json:"company_country"`
}

type LocationInfo struct {
	Continent      string  `json:"continent"`
	Country        string  `json:"country"`
	CountryCode    string  `json:"country_code"`
	Region         string  `json:"region"`
	Province       string  `json:"province"`
	City           string  `json:"city"`
	District       string  `json:"district"`
	Street         string  `json:"street"`
	Radius         string  `json:"radius"`
	AreaCode       string  `json:"area_code"`
	PostalCode     string  `json:"postal_code"`
	CityCode       string  `json:"city_code"`
	Timezone       string  `json:"timezone"`
	Elevation      string  `json:"elevation"`
	WeatherStation string  `json:"weather_station"`
	Latitude       float64 `json:"latitude"`
	Longitude      float64 `json:"longitude"`
	Formatted      string  `json:"formatted"`
}

type SecurityInfo struct {
	IsProxy      bool   `json:"is_proxy"`
	IsVPN        bool   `json:"is_vpn"`
	IsTor        bool   `json:"is_tor"`
	IsDatacenter bool   `json:"is_datacenter"`
	IsHosting    bool   `json:"is_hosting"`
	IsMobile     bool   `json:"is_mobile"`
	RiskScore    int    `json:"risk_score"`
	RiskTag      string `json:"risk_tag"`
	Type         string `json:"type"`
	Provider     string `json:"provider"`
}

type IPTypeBadge struct {
	Code         string `json:"code"`
	Label        string `json:"label"`
	RawUsageType string `json:"raw_usage_type"`
}

type SourceInfo struct {
	GeoSource        string `json:"geo_source"`
	ASNSource        string `json:"asn_source"`
	ISPSource        string `json:"isp_source"`
	SecuritySource   string `json:"security_source"`
	ProxySource      string `json:"proxy_source"`
	VPNSource        string `json:"vpn_source"`
	TorSource        string `json:"tor_source"`
	HostingSource    string `json:"hosting_source"`
	DatacenterSource string `json:"datacenter_source"`
	MobileSource     string `json:"mobile_source"`
	RiskSource       string `json:"risk_source"`
	TypeSource       string `json:"type_source"`
}

type NATInfo struct {
	Detected        bool   `json:"detected"`
	TypeCode        string `json:"type_code"`
	TypeName        string `json:"type_name"`
	TypeNameZH      string `json:"type_name_zh"`
	HasNAT          *bool  `json:"has_nat"`
	Confidence      string `json:"confidence"`
	Method          string `json:"method"`
	Description     string `json:"description"`
	LocalIP         string `json:"local_ip"`
	PublicIP        string `json:"public_ip"`
	PublicPort      int    `json:"public_port"`
	IPv4Supported   bool   `json:"ipv4_supported"`
	IPv6Supported   bool   `json:"ipv6_supported"`
	GatheringState  string `json:"gathering_state"`
	ConnectionMode  string `json:"connection_mode"`
	SelectedType    string `json:"selected_candidate_type"`
	RelayAvailable  bool   `json:"relay_available"`
	DirectAvailable bool   `json:"direct_available"`
}

type BrowserNATReportRequest struct {
	UserAgent               string             `json:"user_agent"`
	HTTPPublicIP            string             `json:"http_public_ip"`
	Candidates              []ICECandidateInfo `json:"candidates"`
	Probes                  []BrowserNATProbe  `json:"probes"`
	GatheringState          string             `json:"gathering_state"`
	ICEConnectionState      string             `json:"ice_connection_state"`
	ConnectionState         string             `json:"connection_state"`
	SelectedCandidateType   string             `json:"selected_candidate_type"`
	SelectedLocalCandidate  ICECandidateInfo   `json:"selected_local_candidate"`
	SelectedRemoteCandidate ICECandidateInfo   `json:"selected_remote_candidate"`
}

type BrowserNATProbe struct {
	Label                   string             `json:"label"`
	URLs                    []string           `json:"urls"`
	Candidates              []ICECandidateInfo `json:"candidates"`
	GatheringState          string             `json:"gathering_state"`
	ICEConnectionState      string             `json:"ice_connection_state"`
	ConnectionState         string             `json:"connection_state"`
	SelectedCandidateType   string             `json:"selected_candidate_type"`
	SelectedLocalCandidate  ICECandidateInfo   `json:"selected_local_candidate"`
	SelectedRemoteCandidate ICECandidateInfo   `json:"selected_remote_candidate"`
}

type ICECandidateInfo struct {
	Candidate      string `json:"candidate"`
	Foundation     string `json:"foundation"`
	Component      string `json:"component"`
	Protocol       string `json:"protocol"`
	Address        string `json:"address"`
	Port           int    `json:"port"`
	Type           string `json:"type"`
	RelatedAddress string `json:"related_address"`
	RelatedPort    int    `json:"related_port"`
	Source         string `json:"source,omitempty"`
}

// 兼容旧代码/旧命名
type CandidateInfo = ICECandidateInfo
