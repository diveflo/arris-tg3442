# arris-tg3442-reboot
Python tool to restart your Arris TG3442* cable modem/router remotely.

## Requirements
* beautifulsoup4
* pycryptodome
* requests
* lxml

## Install
`pip install -r requirements.txt`

## Run
`python3 arris-tg3442-reboot.py`

This will use **default** username, password and router IP.
Use `--help` to learn how to use non-default values.

## Docker
You can also use the provided `Dockerfile` to build and run this tool. For some architectures, an image is also available pre-build from [dockerhub](https://hub.docker.com/r/floriang89/arris-tg3442-reboot/tags).

## Thanks
Most of the heavy-lifiting was already done over in the [MUNIN monitoring tool repo](https://github.com/munin-monitoring/contrib/blob/master/plugins/router/arris-tg3442), especially regarding login.