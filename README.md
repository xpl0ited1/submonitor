# submonitor v1.0.1  by xpl0ited1

---
### Description
Subdomain monitor with reporting capabilities to Slack, Discord and Telegram


### Usage:

Configure the scanning targets on the targets.txt file, set the reporting config at the config.yaml,
then create a cronjob to execute every day

Download the compiled binary from the releases section: https://github.com/xpl0ited1/submonitor/releases/

Or compile it by yourself

```bash
git clone https://github.com/xpl0ited1/submonitor/
cd submonitor
go build main.go
```

The config.yaml file and targets.txt file must be on the same path where you are executing the binary because **ONLY** for now it will load the files from the same directory of the binary


## Contribute

If you would like contribute with this project just ping me on twitter @xpl0ited1 or create a pull request


