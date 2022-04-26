package scanners

type CensysCertResultsBase struct {
	Status   string
	MetaData CensysCertResultsMetadata
	Results  []CensysResults
}

type CensysCertResultsMetadata struct {
	Query       string
	Count       int
	BackendTime int
	Page        int
	Pages       int
}

type CensysResults struct {
	Parsed ParsedCensysResults
}

type ParsedCensysResults struct {
	Names []string
}

//ThreatCrowd
type ThreatCrowdResult struct {
	ResponseCode string   `json:"response_code"`
	Subdomains   []string `json:"subdomains"`
}

//Shodan

type ShodanResult struct {
	Domain string       `json:"domain"`
	Data   []ShodanData `json:"data"`
}

type ShodanData struct {
	Subdomain string `json:"subdomain"`
	Type      string `json:"type"`
	Value     string `json:"value"`
	LastSeen  string `json:"last_seen"`
}

//SecurityTrails
type SecurityTrailsResult struct {
	Subdomains []string `json:"subdomains"`
}
