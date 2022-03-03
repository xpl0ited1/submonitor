# submonitor  by xpl0ited1

---
### Description
Subdomain monitor with reporting capabilities to Slack, Discord and Telegram


### Usage:

Configure the scanning targets on the targets.txt file, set the reporting config at the config.yaml,
then create a cronjob to execute every day

```
crontab -e

0 8 * * * /usr/bin/submonitor
```

Download the compiled binary from the releases section: https://github.com/xpl0ited1/submonitor/releases/

Or compile it by yourself

```bash
git clone https://github.com/xpl0ited1/submonitor/
cd submonitor
go build main.go

./submonitor -h
submonitor v1.0.2
  -c    path to the config.yaml file (default: $HOME/.config/submonitor/config.yaml)
  -t    path to the targets.txt file (default: $HOME/.config/submonitor/targets.txt)
```


## Contribute

If you would like contribute with this project just ping me on twitter @xpl0ited1 or create a pull request


