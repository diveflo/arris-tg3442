from firmware import get_firmware_handler

from bs4 import BeautifulSoup
from Crypto.Cipher import AES
import hashlib
import json
import re
import requests
import sys
import argparse


def getOptions(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(description="Reboot Arris TG3442* cable router remotely.")
    parser.add_argument("-u", "--username", help="router login username", action='store', dest='username', default='admin')
    parser.add_argument("-p", "--password", help="router login password", action='store', dest='password', default='password')
    parser.add_argument("-t", "--target", help="router IP address/url (prepended by http)", action='store', dest='url', default='http://192.168.100.1')

    if (len(args) == 0):
        parser.print_help()
        if not input("\n\nDo you want to run using default user, password and router IP? (y/n): ").lower().strip()[:1] == "y":
            sys.exit(1)

    options = parser.parse_args(args)
    return options


def login(session, url, username, password):
    r = session.get(f"{url}")
    # parse HTML
    soup = BeautifulSoup(r.text, "lxml")

    modem = get_firmware_handler(soup)

    (salt, iv) = modem.get_salt_and_iv()

    current_session_id = re.search(r".*var currentSessionId = '(.+)';.*", soup.head.text)[1]

    key = hashlib.pbkdf2_hmac(
        'sha256',
        bytes(password.encode("ascii")),
        salt,
        iterations=1000,
        dklen=128/8
    )

    secret = {"Password": password, "Nonce": current_session_id}
    plaintext = bytes(json.dumps(secret).encode("ascii"))
    associated_data = "loginPassword"

    cipher = AES.new(key, AES.MODE_CCM, iv)
    cipher.update(bytes(associated_data.encode("ascii")))
    encrypt_data = cipher.encrypt(plaintext)
    encrypt_data += cipher.digest()

    login_data = modem.get_login_data(encrypt_data, username, salt, iv, associated_data)

    r = session.put(
        f"{url}/php/ajaxSet_Password.php",
        headers={
            "Content-Type": "application/json",
            "csrfNonce": "undefined"
        },
        data=json.dumps(login_data)
    )

    if not r.ok or json.loads(r.text)['p_status'] == "Fail":
        print("login failure", file=sys.stderr)
        exit(-1)

    result = json.loads(r.text)

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

    r = session.post(f"{url}/php/ajaxSet_Session.php")


def _unpad(s):
    return s[:-ord(s[len(s) - 1:])]


def restart(session):
    restart_request_data = {"RestartReset": "Restart"}
    session.put(f"{url}/php/ajaxSet_status_restart.php", data=json.dumps(restart_request_data))


if __name__ == "__main__":
    userArguments = getOptions()

    url = userArguments.url
    username = userArguments.username
    password = userArguments.password

    session = requests.Session()

    login(session, url, username, password)
    print("Login successfull")

    print("Attempting restart - this can take a few minutes.")
    restart(session)
