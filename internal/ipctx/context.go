package ipctx

import "time"

type CacheSource string

const (
	CacheSourceNone   CacheSource = "none"
	CacheSourceL1     CacheSource = "l1"
	CacheSourceMongo  CacheSource = "mongo"
	CacheSourceIPInfo CacheSource = "ipinfo"
)

type PrivacyFlags struct {
	VPN              bool   `json:"vpn" bson:"vpn"`
	Proxy            bool   `json:"proxy" bson:"proxy"`
	Tor              bool   `json:"tor" bson:"tor"`
	Relay            bool   `json:"relay" bson:"relay"`
	Hosting          bool   `json:"hosting" bson:"hosting"`
	Service          string `json:"service" bson:"service"`
	ResidentialProxy bool   `json:"residential_proxy" bson:"residential_proxy"`
}

type Context struct {
	IP          string       `json:"ip" bson:"ip"`
	CountryCode string       `json:"country_code" bson:"country_code"`
	CountryName string       `json:"country_name" bson:"country_name"`
	Region      string       `json:"region" bson:"region"`
	City        string       `json:"city" bson:"city"`
	Privacy     PrivacyFlags `json:"privacy" bson:"privacy"`
	LookupError string       `json:"lookup_error,omitempty" bson:"lookup_error,omitempty"`
	LookupTime  time.Time    `json:"lookup_time" bson:"lookup_time"`
}

func (c Context) RiskTypes() []string {
	var risks []string
	if c.Privacy.VPN {
		risks = append(risks, "vpn")
	}
	if c.Privacy.Proxy {
		risks = append(risks, "proxy")
	}
	if c.Privacy.Tor {
		risks = append(risks, "tor")
	}
	if c.Privacy.Relay {
		risks = append(risks, "relay")
	}
	if c.Privacy.Hosting {
		risks = append(risks, "hosting")
	}
	if c.Privacy.ResidentialProxy {
		risks = append(risks, "residential_proxy")
	}
	return risks
}
