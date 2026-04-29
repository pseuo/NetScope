package provider

import (
	"net"

	"github.com/oschwald/geoip2-golang"
)

type DBIPProvider struct {
	cityDB    *geoip2.Reader
	countryDB *geoip2.Reader
	asnDB     *geoip2.Reader
}

type DBIPResult struct {
	Country     string
	CountryCode string
	Region      string
	City        string
	PostalCode  string
	Timezone    string
	Latitude    float64
	Longitude   float64

	ASN             uint
	ASNOrganization string
}

func NewDBIPProvider(cityPath, countryPath, asnPath string) (*DBIPProvider, error) {
	var cityDB *geoip2.Reader
	var countryDB *geoip2.Reader
	var asnDB *geoip2.Reader
	var err error

	if cityPath != "" {
		cityDB, err = geoip2.Open(cityPath)
		if err != nil {
			return nil, err
		}
	}

	if countryPath != "" {
		countryDB, err = geoip2.Open(countryPath)
		if err != nil {
			if cityDB != nil {
				_ = cityDB.Close()
			}
			return nil, err
		}
	}

	if asnPath != "" {
		asnDB, err = geoip2.Open(asnPath)
		if err != nil {
			if cityDB != nil {
				_ = cityDB.Close()
			}
			if countryDB != nil {
				_ = countryDB.Close()
			}
			return nil, err
		}
	}

	return &DBIPProvider{cityDB: cityDB, countryDB: countryDB, asnDB: asnDB}, nil
}

func (p *DBIPProvider) Close() error {
	if p.cityDB != nil {
		_ = p.cityDB.Close()
	}
	if p.countryDB != nil {
		_ = p.countryDB.Close()
	}
	if p.asnDB != nil {
		_ = p.asnDB.Close()
	}
	return nil
}

func (p *DBIPProvider) Query(ipStr string) (*DBIPResult, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, nil
	}

	res := &DBIPResult{}

	if p.cityDB != nil {
		city, err := p.cityDB.City(ip)
		if err == nil && city != nil {
			res.Country = city.Country.Names["zh-CN"]
			if res.Country == "" {
				res.Country = city.Country.Names["en"]
			}
			res.CountryCode = city.Country.IsoCode

			if len(city.Subdivisions) > 0 {
				res.Region = city.Subdivisions[0].Names["zh-CN"]
				if res.Region == "" {
					res.Region = city.Subdivisions[0].Names["en"]
				}
			}

			res.City = city.City.Names["zh-CN"]
			if res.City == "" {
				res.City = city.City.Names["en"]
			}
			res.PostalCode = city.Postal.Code
			res.Timezone = city.Location.TimeZone
			res.Latitude = city.Location.Latitude
			res.Longitude = city.Location.Longitude
		}
	}

	if p.countryDB != nil && (res.Country == "" || res.CountryCode == "") {
		country, err := p.countryDB.Country(ip)
		if err == nil && country != nil {
			if res.Country == "" {
				res.Country = country.Country.Names["zh-CN"]
				if res.Country == "" {
					res.Country = country.Country.Names["en"]
				}
			}
			if res.CountryCode == "" {
				res.CountryCode = country.Country.IsoCode
			}
		}
	}

	if p.asnDB != nil {
		asn, err := p.asnDB.ASN(ip)
		if err == nil && asn != nil {
			res.ASN = asn.AutonomousSystemNumber
			res.ASNOrganization = asn.AutonomousSystemOrganization
		}
	}

	return res, nil
}
