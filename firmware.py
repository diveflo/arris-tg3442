import binascii
import json
import os
import re

from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from requests.sessions import Session


def get_firmware_handler(soup: BeautifulSoup):
    if bool(str(soup.head).count("01.01.117.01.EURO")):
        print("Auto-detected firmware version 01.01.117.01.EURO")
        return FirmwareMid2018(soup)
    elif bool(str(soup.head).count("01.02.037.03.12.EURO.SIP")):
        print("Auto-detected firmware version 01.02.037.03.12.EURO.SIP")
        return FirmwareEarly2019(soup)
    elif bool(str(soup.head).count("01.02.068.10.EURO.SIP")):
        print("Auto-detected firmware version 01.02.068.10.EURO.SIP")
        return FirmwareMid2020(soup)
    elif bool(str(soup.head).count("01.02.068.11.EURO.PC20")):
        print("Auto-detected firmware version 01.02.068.11.EURO.PC20")
        return FirmwareMid2020(soup)
    else:
        raise NotImplementedError("Did not detect any known firmware version - please open a GitHub issue with your firmware version")


class Firmware():
    def __init__(self, soup: BeautifulSoup):
        self.soup = soup

    def get_salt_and_iv(self) -> tuple:
        pass

    def get_login_data(self, encrypted_data: bytes, username: str, salt: str, iv: str, associated_data: str) -> dict:
        pass

    def login(self, session: Session, url: str, login_data: dict) -> str:
        pass

    def get_csrf_nonce(self, login_response, key: bytes, iv: str):
        pass

    def restart(self, session: Session, url: str):
        pass


class FirmwareMid2020(Firmware):
    def get_salt_and_iv(self):
        their_salt = re.search(r".*var mySalt = '(.+)';.*", str(self.soup.head))[1]
        their_iv = re.search(r".*var myIv = '(.+)';.*", str(self.soup.head))[1]
        salt = bytes.fromhex(their_salt)
        iv = bytes.fromhex(their_iv)

        return (salt, iv)

    def get_login_data(self, encrypted_data: bytes, username: str, salt: str, iv: str, associated_data: str):
        return {
            'EncryptData': binascii.hexlify(encrypted_data).decode("ascii"),
            'Name': username,
            'AuthData': associated_data
        }

    def login(self, session: Session, url: str, login_data: dict):
        return session.post(
            f"{url}/php/ajaxSet_Password.php",
            headers={
                "Content-Type": "application/json",
                "csrfNonce": "undefined"
            },
            data=json.dumps(login_data)
        )

    def get_csrf_nonce(self, login_response, key: bytes, iv: str):
        if (login_response["p_status"] == "Lockout"):
           raise Exception(f"Login failed. Lockout reported. Wait {login_response['p_waitTime']} minute/s.")

        cipher = AES.new(key, AES.MODE_CCM, iv)
        cipher.update(bytes("nonce".encode()))
        decrypted_data = cipher.decrypt(bytes.fromhex(login_response['encryptData']))

        return decrypted_data[:32].decode()

    def restart(self, session: Session, url: str):
        restart_request_data = {"RestartReset": "Restart"}
        response = session.post(f"{url}/php/ajaxSet_status_restart.php", data=json.dumps(restart_request_data))
        if not response.ok:
            response.raise_for_status()


class FirmwareEarly2019(Firmware):
    def get_salt_and_iv(self):
        their_salt = re.search(r".*var mySalt = '(.+)';.*", str(self.soup.head))[1]
        their_iv = re.search(r".*var myIv = '(.+)';.*", str(self.soup.head))[1]
        salt = bytes.fromhex(their_salt)
        iv = bytes.fromhex(their_iv)

        return (salt, iv)

    def get_login_data(self, encrypted_data: bytes, username: str, salt: str, iv: str, associated_data: str):
        return {
            'EncryptData': binascii.hexlify(encrypted_data).decode("ascii"),
            'Name': username,
            'AuthData': associated_data
        }

    def login(self, session: Session, url: str, login_data: dict):
        return session.put(
            f"{url}/php/ajaxSet_Password.php",
            headers={
                "Content-Type": "application/json",
                "csrfNonce": "undefined"
            },
            data=json.dumps(login_data)
        )

    def get_csrf_nonce(self, login_response, key: bytes, iv: str):
        cipher = AES.new(key, AES.MODE_CCM, iv)
        cipher.update(bytes("nonce".encode()))
        decrypted_data = cipher.decrypt(bytes.fromhex(login_response['encryptData']))

        return decrypted_data[:32].decode()

    def restart(self, session: Session, url: str):
        restart_request_data = {"RestartReset": "Restart"}
        response = session.put(f"{url}/php/ajaxSet_status_restart.php", data=json.dumps(restart_request_data))
        if not response.ok:
            response.raise_for_status()


class FirmwareMid2018(Firmware):
    def get_salt_and_iv(self):
        salt = os.urandom(8)
        iv = os.urandom(8)
        return (salt, iv)

    def get_login_data(self, encrypted_data: bytes, username: str, salt: str, iv: str, associated_data: str):
        return {
            'EncryptData': binascii.hexlify(encrypted_data).decode("ascii"),
            'Name': username,
            'Salt': binascii.hexlify(salt).decode("ascii"),
            'Iv': binascii.hexlify(iv).decode("ascii"),
            'AuthData': associated_data
        }

    def login(self, session: Session, url: str, login_data: dict):
        return session.put(
            f"{url}/php/ajaxSet_Password.php",
            headers={
                "Content-Type": "application/json",
                "csrfNonce": "undefined"
            },
            data=json.dumps(login_data)
        )

    def get_csrf_nonce(self, login_response, key: bytes, iv: str):
        return login_response['nonce']

    def restart(self, session: Session, url: str):
        restart_request_data = {"RestartReset": "Restart"}
        response = session.put(f"{url}/php/ajaxSet_status_restart.php", data=json.dumps(restart_request_data))
        if not response.ok:
            response.raise_for_status()
