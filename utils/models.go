package utils

//ARF
type ARFTargets struct {
	Targets []ARFTarget
}

type ARFTarget struct {
	ID         string `json:"id"`
	DomainName string `json:"domain_name"`
}
