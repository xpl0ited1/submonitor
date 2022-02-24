package main

import (
	"errors"
	"flag"
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
	targetsFilePath = utils.GetCurrentUserHome() + "/.config/submonitor/targets.txt"
	configFilePath  = utils.GetCurrentUserHome() + "/.config/submonitor/config.yaml"
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

	flag.Parse()
	targetsFilePath = *targetsFilePathFlag
	configFilePath = *configFilePathFlag

	utils.Init(configFilePath)
	checkFileExists()
	doScan()
}

func checkFileExists() {
	if _, err := os.Stat(targetsFilePath); errors.Is(err, os.ErrNotExist) {
		// path/to/whatever does not exist
		log.Fatalf("%s does not exist", targetsFilePath)
	}
	if _, err := os.Stat(configFilePath); errors.Is(err, os.ErrNotExist) {
		// path/to/whatever does not exist
		log.Fatalf("%s does not exist", configFilePath)
	}
}

func doScan() {
	for _, domain := range utils.ReadResults(targetsFilePath) {
		var subs []string
		var resultsFilename = utils.GenerateFileName(domain)

		//Scan
		subs = append(subs, scanners.GetHackertarget(domain)...)
		if utils.GetConfig().SHODAN_APIKEY != "" {
			subs = append(subs, scanners.GetShodan(domain)...)
		}
		if utils.GetConfig().SECTRAILS_APIKEY != "" {
			subs = append(subs, scanners.GetSectrails(domain)...)
		}

		subs = utils.Unique(subs)

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
		bots.SendAttachments(resultsFilename)
	}
}
