package scanners

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"submonitor/utils"
	"time"
)

const (
	SECURITYTRAILS_API_URL = "https://api.securitytrails.com/v1/"
	SHODAN_API_URL         = "https://api.shodan.io/dns/domain/"
	HACKERTARGET_URL       = "https://api.hackertarget.com/hostsearch/?q="
	THREATCROWD_URL        = "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain="
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

	if dat["message"] == "You've exceeded the usage limits for your account." {
		log.Printf("[SECURITY TRAILS] You've exceeded the usage limits for your account.")
		return subs
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

func GetThreatCrowd(domain string) []string {
	var subs []string
	url := THREATCROWD_URL + domain

	req, _ := http.NewRequest("GET", url, nil)

	req.Header.Add("Accept", "application/json")

	res, _ := http.DefaultClient.Do(req)

	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)

	var dat map[string]interface{}
	if err := json.Unmarshal(body, &dat); err != nil {
		return subs
		//panic(err)
	}

	for _, sub := range dat["subdomains"].([]interface{}) {
		subs = append(subs, sub.(string))
	}

	return subs
}

func BruteForce(words []string, resolverIP, domain string, timeout int) []string {
	var subs []string

	if len(resolverIP) > 0 {
		//Determine if the resolverIP comes with a port ex: 8.8.8.8:53
		var dnsResolverIP string

		if len(strings.Split(resolverIP, ":")) > 1 {
			dnsResolverIP = resolverIP
		} else {
			dnsResolverIP += resolverIP + ":53"
		}

		var (
			dnsResolverProto     = "udp"   // Protocol to use for the DNS resolver
			dnsResolverTimeoutMs = timeout // Timeout (ms) for the DNS resolver (optional)
		)

		dialer := &net.Dialer{
			Resolver: &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{
						Timeout: time.Duration(dnsResolverTimeoutMs) * time.Millisecond,
					}
					return d.DialContext(ctx, dnsResolverProto, dnsResolverIP)
				},
			},
		}

		dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		}

		http.DefaultTransport.(*http.Transport).DialContext = dialContext

		for _, word := range words {
			ips, _ := dialer.Resolver.LookupHost(context.Background(), word+"."+domain)

			if len(ips) > 0 {
				subs = append(subs, word+"."+domain)
			}
		}
	} else {
		for _, word := range words {
			ips, _ := net.LookupIP(word + "." + domain)

			if len(ips) > 0 {
				subs = append(subs, word+"."+domain)
			}
		}
	}

	return subs
}
