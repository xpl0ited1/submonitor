package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"submonitor/bots"
	"submonitor/scanners"
	"submonitor/utils"
)

/*
 Subdomain monitor v1.0.1
 by: xpl0ited1 (Bastian Muhlhauser)
 24-02-2022
 TODO: Multithreading
 TODO: Censys.io
 TODO: Certspotter
 TODO: DNS Bruteforcing
 TODO: Implement command handlers on bots
*/

var (
	targetsFilePath     = utils.GetCurrentUserHome() + "/.config/submonitor/targets.txt"
	configFilePath      = utils.GetCurrentUserHome() + "/.config/submonitor/config.yaml"
	subdomainsBrutePath = utils.GetCurrentUserHome() + "/.config/submonitor/brute.txt"
	dnsTimeout          = 5000
)

func main() {
	currentUserHome := utils.GetCurrentUserHome()

	targetsFilePathFlag := flag.String("t",
		currentUserHome+"/.config/submonitor/targets.txt",
		"path to the targets.txt file (default: $HOME/.config/submonitor/targets.txt",
	)

	configFilePathFlag := flag.String("c",
		currentUserHome+"/.config/submonitor/config.yaml",
		"path to the config.yaml file (default: $HOME/.config/submonitor/config.yaml)",
	)

	resolverFlag := flag.String("r", "", "dns server using for resolving subdomains. ex.: 8.8.8.8:53")

	subdomainsBruteFlag := flag.String("w",
		currentUserHome+"/.config/submonitor/brute.txt",
		"path to the wordlists that will be used to bruteforce subdomains (default: $HOME/.config/submonitor/brute.txt")

	bruteForceFlag := flag.Bool("b", false, "if specified the tool will try to bruteforce subdomains")

	dnsTimeoutFlag := flag.Int("dt", 5000, "timeout for dns queries when bruteforcing (default: 5000)")

	flag.Parse()
	targetsFilePath = *targetsFilePathFlag
	configFilePath = *configFilePathFlag
	subdomainsBrutePath = *subdomainsBruteFlag
	dnsTimeout = *dnsTimeoutFlag

	utils.Init(configFilePath)
	checkFileExists(*bruteForceFlag)
	doScan(*bruteForceFlag, *resolverFlag)
}

func checkFileExists(isBruteForcing bool) {
	if _, err := os.Stat(targetsFilePath); errors.Is(err, os.ErrNotExist) {
		// path/to/whatever does not exist
		log.Fatalf("%s does not exist", targetsFilePath)
	}
	if _, err := os.Stat(configFilePath); errors.Is(err, os.ErrNotExist) {
		// path/to/whatever does not exist
		log.Fatalf("%s does not exist", configFilePath)
	}
	if isBruteForcing {
		if _, err := os.Stat(subdomainsBrutePath); errors.Is(err, os.ErrNotExist) {
			// path/to/whatever does not exist
			log.Fatalf("%s does not exist", subdomainsBrutePath)
		}
	}
}

func doScan(isBruteForcing bool, resolver string) {
	for _, domain := range utils.ReadResults(targetsFilePath) {
		var subs []string
		var resultsFilename = utils.GenerateFileName(domain)

		//Scan
		subs = append(subs, scanners.GetThreatCrowd(domain)...)
		subs = append(subs, scanners.GetHackertarget(domain)...)
		if utils.GetConfig().SHODAN_APIKEY != "" {
			subs = append(subs, scanners.GetShodan(domain)...)
		}
		if utils.GetConfig().SECTRAILS_APIKEY != "" {
			subs = append(subs, scanners.GetSectrails(domain)...)
		}

		if isBruteForcing {
			subs = append(subs, scanners.BruteForce(utils.ReadResults(subdomainsBrutePath), resolver, domain, dnsTimeout)...)
		}

		subs = utils.Unique(subs)
		for _, sub := range subs {
			fmt.Println(sub)
		}

		//Load last results
		last_results := utils.ReadResults(utils.GenerateFileNameAll(domain))

		diff := utils.Difference(subs, last_results)

		//Append last with new to make a whole file
		allSubs := append(last_results, subs...)
		allSubs = utils.Unique(allSubs)

		//Replace last results with last+new
		utils.SaveResults(utils.GenerateFileNameAll(domain), allSubs)

		//Save new results
		utils.SaveResults(resultsFilename, diff)

		//Report with the bots
		bots.Report(diff, domain)
		if len(diff) > 0 {
			bots.SendAttachments(resultsFilename)
		}
	}
}
