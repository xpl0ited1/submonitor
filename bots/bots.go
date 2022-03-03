package bots

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"submonitor/utils"
)

func sendToSlack(subs []string, domain string) {
	var jsonStr = []byte(fmt.Sprintf(`{"text":"%s"}`, craftMessage(subs, domain)))

	req, _ := http.NewRequest("POST", utils.GetConfig().SLACK_WEBHOOK, bytes.NewBuffer(jsonStr))

	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")

	_, _ = http.DefaultClient.Do(req)
}

func sendToTelegram(subs []string, domain string) {
	send_text := "https://api.telegram.org/bot" +
		utils.GetConfig().TELEGRAM_BOT_TOKEN +
		"/sendMessage?chat_id=" +
		utils.GetConfig().TELEGRAM_CHAT_ID +
		"&parse_mode=Markdown&text=" +
		craftMessage(subs, domain)
	req, _ := http.NewRequest("GET", send_text, nil)

	_, _ = http.DefaultClient.Do(req)
}

func sendToDiscord(subs []string, domain string) {
	var jsonStr = []byte(fmt.Sprintf(`{"username":"%s","content": "%s"}`, utils.GetConfig().DISCORD_BOT_NAME, craftMessage(subs, domain)))

	req, _ := http.NewRequest("POST", utils.GetConfig().DISCORD_WEBHOOK, bytes.NewBuffer(jsonStr))

	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")

	_, _ = http.DefaultClient.Do(req)
}

func craftMessage(subs []string, domain string) string {
	msg := "Found %d new subdomains for %s"
	msg = fmt.Sprintf(msg, len(subs), domain)
	return msg
}

func Report(subs []string, domain string) {
	if utils.GetConfig().SLACK_WEBHOOK != "" {
		sendToSlack(subs, domain)
	}
	if utils.GetConfig().TELEGRAM_BOT_TOKEN != "" && utils.GetConfig().TELEGRAM_CHAT_ID != "" {
		sendToTelegram(subs, domain)
	}
	if utils.GetConfig().DISCORD_WEBHOOK != "" {
		sendToDiscord(subs, domain)
	}
}

func SendAttachments(resultsFilename string) {
	if utils.GetConfig().DISCORD_WEBHOOK != "" {
		sendAttachmentToDiscord(resultsFilename)
	}
	if utils.GetConfig().TELEGRAM_CHAT_ID != "" && utils.GetConfig().TELEGRAM_BOT_TOKEN != "" {
		sendAttachmentToTelegram(resultsFilename)
	}
	if utils.GetConfig().SLACK_WEBHOOK != "" {
		sendAttachmentToSlack(resultsFilename)
	}
}

func sendAttachmentToDiscord(resultsFilename string) {
	fileDir := utils.GetConfig().RESULTS_PATH
	filePath := path.Join(fileDir, resultsFilename)

	file, _ := os.Open(filePath)
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("file1", filepath.Base(file.Name()))
	io.Copy(part, file)
	p2, _ := writer.CreateFormField("payload_json")
	p2.Write([]byte(fmt.Sprintf(`{"username":"%s","content": "%s"}`, utils.GetConfig().DISCORD_BOT_NAME, "")))
	writer.Close()

	r, _ := http.NewRequest("POST", utils.GetConfig().DISCORD_WEBHOOK, body)
	r.Header.Add("Content-Type", writer.FormDataContentType())
	client := &http.Client{}
	client.Do(r)
}

func sendAttachmentToTelegram(resultsFilename string) {
	send_file := "https://api.telegram.org/bot" +
		utils.GetConfig().TELEGRAM_BOT_TOKEN +
		"/sendDocument"

	fileDir := utils.GetConfig().RESULTS_PATH
	fileName := resultsFilename
	filePath := path.Join(fileDir, fileName)

	file, _ := os.Open(filePath)
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("document", filepath.Base(file.Name()))
	io.Copy(part, file)
	p2, _ := writer.CreateFormField("chat_id")
	p2.Write([]byte(utils.GetConfig().TELEGRAM_CHAT_ID))
	writer.Close()

	r, _ := http.NewRequest("POST", send_file, body)
	r.Header.Add("Content-Type", writer.FormDataContentType())
	client := &http.Client{}
	client.Do(r)
}

//TODO: Try to implement file upload to slackwebhook if exists
func sendAttachmentToSlack(resultsFilename string) {

}
