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
