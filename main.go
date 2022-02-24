package main

import (
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

func main() {
	doScan()
}

func doScan() {
	for _, domain := range utils.ReadResults("targets.txt") {
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
