package utils

import (
	"bufio"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"os"
	"time"
)

func Unique(stringSlice []string) []string {
	keys := make(map[string]bool)
	var list []string
	for _, entry := range stringSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

type conf struct {
	SECTRAILS_APIKEY   string `yaml:"securitytrails_apikey"`
	SHODAN_APIKEY      string `yaml:"shodan_apikey"`
	SLACK_WEBHOOK      string `yaml:"slack_webhook"`
	TELEGRAM_BOT_TOKEN string `yaml:"telegram_bot_token"`
	TELEGRAM_CHAT_ID   string `yaml:"telegram_chat_id"`
	RESULTS_PATH       string `yaml:"results_path"`
	DISCORD_WEBHOOK    string `yaml:"discord_webhook"`
	DISCORD_BOT_NAME   string `yaml:"discord_bot_name"`
}

//TODO: Refactor this as for better coding practices
func (c *conf) getConf() *conf {

	yamlFile, err := ioutil.ReadFile("config.yaml")
	if err != nil {
		log.Printf("yamlFile.Get err   #%v ", err)
	}
	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}

	return c
}

func GetConfig() conf {
	var c conf
	c.getConf()
	return c
}

func GenerateFileName(domain string) string {
	filename := ""
	currentTime := time.Now()
	filename = currentTime.Format("01-02-2006") + domain + ".txt"
	return filename
}

func GenerateFileNameAll(domain string) string {
	filename := ""
	filename = domain + ".txt"
	return filename
}

func GenerateLastFileName(domain string) string {
	filename := ""
	currentTime := time.Now().Add(-24 * time.Hour)
	filename = currentTime.Format("01-02-2006") + domain + ".txt"
	return filename
}

func SaveResults(filename string, subs []string) {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	if err != nil {
		log.Fatalf("failed creating file: %s", err)
	}

	datawriter := bufio.NewWriter(file)

	for _, data := range subs {
		_, _ = datawriter.WriteString(data + "\n")
	}

	datawriter.Flush()
	file.Close()
}

func ReadResults(filename string) []string {
	file, err := os.Open(filename)
	if err != nil {
		return nil
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}

func Difference(newResults, lastResults []string) []string {
	mb := make(map[string]struct{}, len(lastResults))
	for _, x := range lastResults {
		mb[x] = struct{}{}
	}
	var diff []string
	for _, x := range newResults {
		if _, found := mb[x]; !found {
			diff = append(diff, x)
		}
	}
	return diff
}

func ReplaceFileContent(filename string, subs []string) {
	// Read Write Mode
	file, err := os.OpenFile(filename, os.O_RDWR, 0644)

	if err != nil {
		log.Fatalf("failed creating file: %s", err)
	}

	datawriter := bufio.NewWriter(file)

	for _, data := range subs {
		_, _ = datawriter.WriteString(data + "\n")
	}

	datawriter.Flush()
	file.Close()
}
