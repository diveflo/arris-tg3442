# arris-tg3442

Python tool to restart and retrieve the phone log of your Arris TG3442* cable modem/router remotely.

## Supported firmware versions

Currently, the following firmware versions are supported:

* 01.01.117.01.EURO
* 01.02.037.03.12.EURO.SIP
* 01.02.068.10.EURO.SIP
* 01.02.068.11.EURO.PC20
* 01.02.068.13.EURO.PC20
* 01.04.046.07.EURO.PC20
* 01.04.046.12.EURO.PC20
* 01.04.046.15.EURO.PC20
* 01.04.046.17.EURO.PC20
* 01.04.046.25.EURO.PC20
* 01.04.137.08.EURO.PC20

## Requirements

* beautifulsoup4
* pycryptodome
* requests

## Install

`pip install -r requirements.txt`

## Run

`python3 arris-tg3442-reboot.py`

This will use **default** username, password and router IP.
Use `--help` to learn how to use non-default values.

### To retrieve phone log

`python3 arris-tg3442-reboot.py phone-log`

Note: phone log isn't persistent and is empty after a restart of the modem

## Docker

You can also use the provided `Dockerfile` to build and run this tool. A pre-built image is also available on [dockerhub](https://hub.docker.com/r/floriang89/arris-tg3442-reboot/tags) for these processor architectures:

* amd64
* arm64
* arm/v7
* arm/v6

## Thanks

Most of the heavy-lifting was already done over in the [MUNIN monitoring tool repo](https://github.com/munin-monitoring/contrib/blob/master/plugins/router/arris-tg3442), especially regarding login.
Thank you [debfx](https://github.com/debfx), [Mershl](https://github.com/Mershl) and [schelmo](https://github.com/schelmo) for enabling support for additional firmwares.
