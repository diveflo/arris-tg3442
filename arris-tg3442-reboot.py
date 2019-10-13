import binascii
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
import hashlib
import json
import re
import requests
import sys
import argparse
import os

def getOptions(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(description="Reboot Arris TG3442* cable router remotely.")
    parser.add_argument("-u", "--username", help="router login username", action='store', dest='username', default='admin')
    parser.add_argument("-p", "--password", help="router login password", action='store', dest='password', default='password')
    parser.add_argument("-t", "--target", help="router IP address/url (prepended by http)", action='store', dest='url', default='http://192.168.100.1')
    options = parser.parse_args(args)
    return options

def login(session, url, username, password):
    """login to """
    # get login page
    r = session.get(f"{url}")
    # parse HTML
    h = BeautifulSoup(r.text, "lxml")
    # get session id from javascript in head
    current_session_id = re.search(r".*var currentSessionId = '(.+)';.*", h.head.text)[1]

    # encrypt password
    salt = os.urandom(8)
    iv = os.urandom(8)
    key = hashlib.pbkdf2_hmac(
        'sha256',
        bytes(password.encode("ascii")),
        salt,
        iterations=1000,
        dklen=128/8
    )
    secret = { "Password": password, "Nonce": current_session_id }
    plaintext = bytes(json.dumps(secret).encode("ascii"))
    associated_data = "loginPassword"
    # initialize cipher
    cipher = AES.new(key, AES.MODE_CCM, iv)
    # set associated data
    cipher.update(bytes(associated_data.encode("ascii")))
    # encrypt plaintext
    encrypt_data = cipher.encrypt(plaintext)
    # append digest
    encrypt_data += cipher.digest()
    # return
    login_data = {
        'EncryptData': binascii.hexlify(encrypt_data).decode("ascii"),
        'Name': username,
        'Salt': binascii.hexlify(salt).decode("ascii"),
        'Iv': binascii.hexlify(iv).decode("ascii"),
        'AuthData': associated_data
    }

    # login
    r = session.put(
        f"{url}/php/ajaxSet_Password.php",
        headers={
            "Content-Type": "application/json",
            "csrfNonce": "undefined"
        },
        data=json.dumps(login_data)
    )

    # parse result
    result = json.loads(r.text)
    # success?
    if result['p_status'] == "Fail":
        print("login failure", file=sys.stderr)
        exit(-1)
    # remember CSRF nonce
    csrf_nonce = result['nonce']

    # prepare headers
    session.headers.update({
        "X-Requested-With": "XMLHttpRequest",
        "csrfNonce": csrf_nonce,
        "Origin": f"{url}/",
        "Referer": f"{url}/"
    })
    # set credentials cookie
    session.cookies.set(
        "credential",
        "eyAidW5pcXVlIjoiMjgwb2FQU0xpRiIsICJmYW1pbHkiOiI4NTIiLCAibW9kZWxuYW1lIjoiV"
        "EcyNDkyTEctODUiLCAibmFtZSI6InRlY2huaWNpYW4iLCAidGVjaCI6dHJ1ZSwgIm1vY2EiOj"
        "AsICJ3aWZpIjo1LCAiY29uVHlwZSI6IldBTiIsICJnd1dhbiI6ImYiLCAiRGVmUGFzc3dkQ2h"
        "hbmdlZCI6IllFUyIgfQ=="
    )

    # set session
    r = session.post(f"{url}/php/ajaxSet_Session.php")

def restart(session):
    restart_request_data = {"RestartReset":"Restart"}

    r2 = session.put(f"{url}/php/ajaxSet_status_restart.php", data=json.dumps(restart_request_data))

# -----------------------------------------------------------------------------
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