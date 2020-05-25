# arris-tg3442-reboot
Python tool to restart your Arris TG3442* cable modem/router remotely.

## Supported firmware versions
Currently, the following firmware versions are supported:
 * AR01.01.117.01_091718_70.PC20.10
 * AR01.02.037.03.12.EURO.SIP

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
You can also use the provided `Dockerfile` to build and run this tool. A pre-built image is also available on [dockerhub](https://hub.docker.com/r/floriang89/arris-tg3442-reboot/tags) for these processor architectures:
 * amd64
 * arm64
 * arm/v7
 * arm/v6

## Thanks
Most of the heavy-lifiting was already done over in the [MUNIN monitoring tool repo](https://github.com/munin-monitoring/contrib/blob/master/plugins/router/arris-tg3442), especially regarding login.