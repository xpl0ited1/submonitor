package bots

import (
	"bytes"
	"fmt"
	"net/http"
	"submonitor/utils"
)

func sendToSlack(subs []string, domain string, resultsFile string) {
	var jsonStr = []byte(fmt.Sprintf(`{"text":"%s"}`, craftMessage(subs, domain, resultsFile)))

	req, _ := http.NewRequest("POST", utils.GetConfig().SLACK_WEBHOOK, bytes.NewBuffer(jsonStr))

	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")

	_, _ = http.DefaultClient.Do(req)
}

func sendToTelegram(subs []string, domain string, resultsFile string) {
	send_text := "https://api.telegram.org/bot" +
		utils.GetConfig().TELEGRAM_BOT_TOKEN +
		"/sendMessage?chat_id=" +
		utils.GetConfig().TELEGRAM_CHAT_ID +
		"&parse_mode=Markdown&text=" +
		craftMessage(subs, domain, resultsFile)
	req, _ := http.NewRequest("GET", send_text, nil)

	_, _ = http.DefaultClient.Do(req)
}

func sendToDiscord(subs []string, domain string, resultsFile string) {
	var jsonStr = []byte(fmt.Sprintf(`{"username":"TeststingDevBot","content": "%s"}`, craftMessage(subs, domain, resultsFile)))

	req, _ := http.NewRequest("POST", utils.GetConfig().DISCORD_WEBHOOK, bytes.NewBuffer(jsonStr))

	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")

	_, _ = http.DefaultClient.Do(req)
}

func craftMessage(subs []string, domain string, resultsFile string) string {
	msg := "Found %d new subdomains for %s, check the findings at %s"
	msg = fmt.Sprintf(msg, len(subs), domain, utils.GetConfig().RESULTS_PATH+resultsFile)
	return msg
}

func Report(subs []string, domain string, resultsFile string) {
	if utils.GetConfig().SLACK_WEBHOOK != "" {
		sendToSlack(subs, domain, resultsFile)
	}
	if utils.GetConfig().TELEGRAM_BOT_TOKEN != "" && utils.GetConfig().TELEGRAM_CHAT_ID != "" {
		sendToTelegram(subs, domain, resultsFile)
	}
	if utils.GetConfig().DISCORD_WEBHOOK != "" {
		sendToDiscord(subs, domain, resultsFile)
	}
}
