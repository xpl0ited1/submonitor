package scanners

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
	"submonitor/utils"
)

const (
	SECURITYTRAILS_API_URL = "https://api.securitytrails.com/v1/"
	SHODAN_API_URL         = "https://api.shodan.io/dns/domain/"
	HACKERTARGET_URL       = "https://api.hackertarget.com/hostsearch/?q="
)

func GetSectrails(domain string) []string {
	var subs []string
	url := SECURITYTRAILS_API_URL + "domain/" + domain + "/subdomains?children_only=false&include_inactive=true"

	req, _ := http.NewRequest("GET", url, nil)

	req.Header.Add("Accept", "application/json")
	req.Header.Add("APIKEY", utils.GetConfig().SECTRAILS_APIKEY)

	res, _ := http.DefaultClient.Do(req)

	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)

	var dat map[string]interface{}
	if err := json.Unmarshal(body, &dat); err != nil {
		panic(err)
	}

	for _, sub := range dat["subdomains"].([]interface{}) {
		subs = append(subs, sub.(string)+"."+domain)
	}

	return subs
}

func GetShodan(domain string) []string {
	var subs []string
	url := SHODAN_API_URL + domain + "?key=" + utils.GetConfig().SHODAN_APIKEY

	req, _ := http.NewRequest("GET", url, nil)

	req.Header.Add("Accept", "application/json")

	res, _ := http.DefaultClient.Do(req)

	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)

	var dat map[string]interface{}
	if err := json.Unmarshal(body, &dat); err != nil {
		panic(err)
	}

	for _, sub := range dat["subdomains"].([]interface{}) {
		subs = append(subs, sub.(string)+"."+domain)
	}

	return subs
}

func GetHackertarget(domain string) []string {
	var subs []string
	url := HACKERTARGET_URL + domain

	req, _ := http.NewRequest("GET", url, nil)

	req.Header.Add("Accept", "application/json")

	res, _ := http.DefaultClient.Do(req)

	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)

	for _, sub := range strings.Split(string(body), "\n") {
		parsed_sub := strings.Split(sub, ",")[0]
		if parsed_sub != "" && parsed_sub != domain {
			subs = append(subs, parsed_sub)
		}
	}

	return subs
}
