import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timedelta

import requests
from bs4 import BeautifulSoup
from Crypto.Cipher import AES

from firmware import get_firmware_handler


def get_options(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(description="Reboot Arris TG3442* cable router remotely.")
    parser.add_argument("-u", "--username", help="router login username", action='store', dest='username', default='admin')
    parser.add_argument("-p", "--password", help="router login password", action='store', dest='password', default='password')
    parser.add_argument("-t", "--target", help="router IP address/url (prepended by http)", action='store', dest='url', default='http://192.168.100.1')
    parser.add_argument("action", nargs='?', choices=('reboot', 'phone-log'), help="the action to send (default to reboot)", action="store", default='reboot')

    if (len(args) == 0):
        parser.print_help()
        if not input("\n\nDo you want to run using default user, password and router IP? (y/n): ").lower().strip()[:1] == "y":
            sys.exit(1)

    options = parser.parse_args(args)
    return options


def login(session, url, username, password):
    response = session.get(f"{url}")
    soup = BeautifulSoup(response.text, "html.parser")

    modem = get_firmware_handler(soup)

    (salt, iv) = modem.get_salt_and_iv()
    key = hashlib.pbkdf2_hmac('sha256', bytes(password.encode("ascii")), salt, iterations=1000, dklen=128//8)

    current_session_id = re.search(r".*var currentSessionId = '(.+)';.*", str(soup.head))[1]
    secret = {"Password": password, "Nonce": current_session_id}
    plaintext = bytes(json.dumps(secret).encode("ascii"))
    associated_data = "loginPassword"

    cipher = AES.new(key, AES.MODE_CCM, iv)
    cipher.update(bytes(associated_data.encode("ascii")))
    encrypted_data = cipher.encrypt(plaintext)
    encrypted_data += cipher.digest()

    login_data = modem.get_login_data(encrypted_data, username, salt, iv, associated_data)

    response = modem.login(session, url, login_data)

    if not response.ok or json.loads(response.text)['p_status'] == "Fail":
        print("login failure", file=sys.stderr)
        exit(-1)

    result = json.loads(response.text)

    csrf_nonce = modem.get_csrf_nonce(result, key, iv)

    session.headers.update({
        "X-Requested-With": "XMLHttpRequest",
        "csrfNonce": csrf_nonce,
        "Origin": f"{url}/",
        "Referer": f"{url}/"
    })

    session.cookies.set(
        "credential",
        "eyAidW5pcXVlIjoiMjgwb2FQU0xpRiIsICJmYW1pbHkiOiI4NTIiLCAibW9kZWxuYW1lIjoiV"
        "EcyNDkyTEctODUiLCAibmFtZSI6InRlY2huaWNpYW4iLCAidGVjaCI6dHJ1ZSwgIm1vY2EiOj"
        "AsICJ3aWZpIjo1LCAiY29uVHlwZSI6IldBTiIsICJnd1dhbiI6ImYiLCAiRGVmUGFzc3dkQ2h"
        "hbmdlZCI6IllFUyIgfQ=="
    )

    response = session.post(f"{url}/php/ajaxSet_Session.php")

    return modem


def format_phone_log_entry(entry):
    call_type = entry["CallType"]
    date = entry["Date"]
    today = datetime.today()
    if date == "PAGE_CALL_LOG_TABLE_TODAY":
        date = today.strftime("%Y-%m-%d")
    elif date == "PAGE_CALL_LOG_TABLE_YESTERDAY":
        date = (today + timedelta(days=-1)).strftime("%Y-%m-%d")
    time = entry["Time"]
    number = entry["ExternalNumber"]
    duration = entry["Duration"]
    msg = f"{call_type} Call on {date} {time} from {number}"
    if duration:
        msg += f" for {duration} minutes"
    return msg


def format_phone_log(log):
    return "\n".join(map(format_phone_log_entry, list(reversed(log))))


if __name__ == "__main__":
    userArguments = get_options()

    url = userArguments.url
    username = userArguments.username
    password = userArguments.password

    session = requests.Session()

    modem = login(session, url, username, password)
    print("Login successful")

    if userArguments.action == "reboot":
        print("Attempting restart")
        modem.restart(session, url)
        print("Restart successfully triggered - this can take a few minutes")
    elif userArguments.action == "phone-log":
        print("Retrieving phone log since last reboot")
        log = modem.get_phone_log(session, url)
        if "PhoneLogRecord" not in log or len(log["PhoneLogRecord"]) == 0:
            print("No entries found")
        else:
            print(format_phone_log(log["PhoneLogRecord"]))
