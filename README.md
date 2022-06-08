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

```
git clone https://github.com/xpl0ited1/submonitor/
cd submonitor
go build main.go

./submonitor -h
submonitor v1.0.3
 -arf
        if specified the tool will report the subdomains to ARF API
  -b    if specified the tool will try to bruteforce subdomains
  -c string
        path to the config.yaml file (default: $HOME/.config/submonitor/config.yaml) 
  -dt int
        timeout for dns queries when bruteforcing (default 5000)
  -r string
        dns server using for resolving subdomains. ex.: 8.8.8.8:53
  -t string
        path to the targets.txt file (default: $HOME/.config/submonitor/targets.txt)
  -w string
        path to the wordlists that will be used to bruteforce subdomains (default: $HOME/.config/submonitor/brute.txt)
```


## Contribute

If you would like contribute with this project just ping me on twitter @xpl0ited1 or create a pull request


