package scanners

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/net/html"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"submonitor/utils"
	"sync"
	"time"
)

const (
	//THREATCROWD_URL        = "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain="
	SECURITYTRAILS_API_URL = "https://api.securitytrails.com/v1/"
	SHODAN_API_URL         = "https://api.shodan.io/dns/domain/"
	HACKERTARGET_URL       = "https://api.hackertarget.com/hostsearch/?q="
	CENSYS_URL             = "https://search.censys.io/api/v1/search/certificates"
	DNSDUMPSTER_URL        = "https://dnsdumpster.com/"
	CRTSH_URL              = "https://crt.sh/?q="
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

	result := SecurityTrailsResult{}
	if err := json.Unmarshal(body, &result); err != nil {
		panic(err)
	}

	for _, sub := range result.Subdomains {
		subs = append(subs, sub+"."+domain)
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

	result := ShodanResult{}
	if err := json.Unmarshal(body, &result); err != nil {
		panic(err)
	}

	for _, sub := range result.Data {
		subs = append(subs, sub.Subdomain+"."+result.Domain)
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

	if !strings.Contains(string(body), "error invalid host\n") {
		for _, sub := range strings.Split(string(body), "\n") {
			parsed_sub := strings.Split(sub, ",")[0]
			if parsed_sub != "" && parsed_sub != domain {
				subs = append(subs, parsed_sub)
			}
		}
	} else {
		log.Printf("[HackerTarget] Invalid Host")
	}

	return subs
}

/*
Deprecated function as the service is down
func GetThreatCrowd(domain string) []string {
	var subs []string
	url := THREATCROWD_URL + domain

	req, _ := http.NewRequest("GET", url, nil)

	req.Header.Add("Accept", "application/json")

	res, err := http.DefaultClient.Do(req)

	if err != nil {
		log.Println(err)
		return subs
	}

	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)

	result := ThreatCrowdResult{}
	if err := json.Unmarshal(body, &result); err != nil {
		return subs
		//panic(err)
	}

	for _, sub := range result.Subdomains {
		subs = append(subs, sub)
	}
	return subs
}*/

func BruteForce(words []string, resolverIP, domain string, timeout int) []string {
	var subs []string
	log.Println("[BruteForce] Starting brute force scan")
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

		subs = BruteForceDialer(words, domain, dialer)
	} else {
		subs = BruteForceNoDialed(words, domain)
	}

	return subs
}

func BruteForceDialer(words []string, domain string, dialer *net.Dialer) (subs []string) {
	var wg sync.WaitGroup
	for _, word := range words {
		wg.Add(1)
		go func(word, domain string, dialer *net.Dialer) {
			defer wg.Done()
			ips, _ := dialer.Resolver.LookupHost(context.Background(), word+"."+domain)

			if len(ips) > 0 {
				subs = append(subs, word+"."+domain)
			}
		}(word, domain, dialer)
	}
	wg.Wait()
	return subs
}

func BruteForceNoDialed(words []string, domain string) (subs []string) {
	var wg sync.WaitGroup
	for _, word := range words {
		wg.Add(1)
		go func(word, domain string) {
			defer wg.Done()
			ips, _ := net.LookupIP(word + "." + domain)

			if len(ips) > 0 {
				subs = append(subs, word+"."+domain)
			}
		}(word, domain)
	}
	wg.Wait()
	return subs
}

func GetCensys(domain string) []string {
	var subs []string
	censysPage := 1
	censysAuthorization := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", utils.GetConfig().CENSYS_API_ID, utils.GetConfig().CENSYS_SECRET)))
	url := CENSYS_URL

	var jsonStr = []byte(fmt.Sprintf(`{"query": "parsed.names: %s","page": %d,"fields": ["parsed.names"],"flatten": false}`, domain, censysPage))

	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", censysAuthorization))

	res, _ := http.DefaultClient.Do(req)

	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)

	var dat = CensysCertResultsBase{}
	if err := json.Unmarshal(body, &dat); err != nil {
		panic(err)
	}

	var tmp_results = []CensysResults{}
	tmp_results = append(tmp_results, dat.Results...)

	for _, item := range tmp_results {
		subs = append(subs, item.Parsed.Names...)
	}

	for censysPage <= dat.MetaData.Pages {
		time.Sleep(5 * time.Second)
		censysPage = censysPage + 1
		jsonStr = []byte(fmt.Sprintf(`{"query": "parsed.names: %s","page": %d,"fields": ["parsed.names"],"flatten": false}`, domain, censysPage))

		req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))

		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Accept", "application/json")
		req.Header.Add("Authorization", fmt.Sprintf("Basic %s", censysAuthorization))

		res, _ := http.DefaultClient.Do(req)

		defer res.Body.Close()
		body, _ := ioutil.ReadAll(res.Body)

		dat = CensysCertResultsBase{}
		if err := json.Unmarshal(body, &dat); err != nil {
			panic(err)
		}
		tmp_results = []CensysResults{}
		tmp_results = append(tmp_results, dat.Results...)

		for _, item := range tmp_results {
			subs = append(subs, item.Parsed.Names...)
		}
	}
	return subs
}

func GetDNSDumpsterCSRFToken() (string, []*http.Cookie) {
	url := DNSDUMPSTER_URL

	req, _ := http.NewRequest("GET", url, nil)

	res, _ := http.DefaultClient.Do(req)

	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)

	re := regexp.MustCompile(`(?s)<input type="hidden" name="csrfmiddlewaretoken" value="(.*?)">`)
	match := re.FindStringSubmatch(string(body))

	if len(match) > 1 {
		return match[1], res.Cookies()
	}
	return "", nil
}

func GetDNSDumpster(domain string) []string {
	csrfToken, cookies := GetDNSDumpsterCSRFToken()
	var csrfCookie string
	for idx := range cookies {
		if cookies[idx].Name == "csrftoken" {
			csrfCookie = cookies[idx].Value
			break
		}
	}
	return DoDNSDumpster(domain, csrfToken, csrfCookie)
}

func ParseDNSDumpsterResponseHTML(htmlResponse string, domain string) (data []string) {

	tkn := html.NewTokenizer(strings.NewReader(htmlResponse))

	var vals []string

	var isTd bool

	for {

		tt := tkn.Next()

		switch {

		case tt == html.ErrorToken:
			return vals

		case tt == html.StartTagToken:

			t := tkn.Token()
			isTd = t.Data == "td"

		case tt == html.TextToken:

			t := tkn.Token()

			if isTd && strings.Contains(t.Data, domain) {
				if t.Data[len(t.Data)-1:] != "." {
					vals = append(vals, t.Data)
				}
			}

			isTd = false
		}
	}
}

func CleanHTMLSubs(data []string) []string {
	blacklist := []string{string('"'), "'", "<", ">", "(", "{", "}", "[", "]", "=", "~", "`", "!", "@", "#", "$", "%", "^", "&", "*", "+", "|", "\\", "/", "?", ":", ";", ",", " "}
	var cleanSubs []string
	for _, sub := range data {
		hasBlacklistedChar := false
		for _, blacklisted := range blacklist {
			if strings.Contains(sub, blacklisted) {
				hasBlacklistedChar = true
				break
			}
		}
		if !hasBlacklistedChar {
			cleanSubs = append(cleanSubs, sub)
		}
	}
	cleanSubs = utils.Unique(cleanSubs)
	return cleanSubs
}

func DoDNSDumpster(domain, csrfToken, csrfCookie string) []string {
	var subs []string

	data := "csrfmiddlewaretoken=" + csrfToken + "&targetip=" + domain + "&user=free&col=on&resource=on"

	req, _ := http.NewRequest("POST", DNSDUMPSTER_URL, bytes.NewBuffer([]byte(data)))

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Referer", DNSDUMPSTER_URL)
	req.Header.Add("Origin", DNSDUMPSTER_URL)
	req.Header.Add("Cookie", "csrftoken="+csrfCookie)
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36")

	res, _ := http.DefaultClient.Do(req)

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)

	if err != nil {
		log.Println(err)
	}

	subs = CleanHTMLSubs(ParseDNSDumpsterResponseHTML(string(body), domain))

	return subs
}

func GetCrtSh(domain string) (subs []string) {
	url := CRTSH_URL + domain

	req, _ := http.NewRequest("GET", url, nil)

	res, err := http.DefaultClient.Do(req)

	if err != nil {
		log.Println(err)
		return subs
	}

	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)

	subs = CleanHTMLSubs(ParseCrtShHTMLResponse(string(body), domain))
	fmt.Println(subs)

	return subs
}

func ParseCrtShHTMLResponse(htmlResponse string, domain string) (data []string) {
	fmt.Println(domain)
	tkn := html.NewTokenizer(strings.NewReader(htmlResponse))

	var vals []string

	var isTd bool

	for {

		tt := tkn.Next()

		switch {

		case tt == html.ErrorToken:
			return vals

		case tt == html.StartTagToken:

			t := tkn.Token()
			isTd = t.Data == "td"

		case tt == html.TextToken:

			t := tkn.Token()

			if isTd && strings.Contains(t.Data, domain) {
				if t.Data[len(t.Data)-1:] != "." {

					vals = append(vals, t.Data)
				}
			}

			isTd = false
		}

	}
}
