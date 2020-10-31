from bs4 import BeautifulSoup
import binascii
from Crypto.Cipher import AES
import json
import os
import re
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


class Firmware():
    def __init__(self, soup: BeautifulSoup):
        self.soup = soup

    def get_salt_and_iv(self) -> tuple:
        pass

    def get_login_data(self, encrypt_data: bytes, username: str, salt: str, iv: str, associated_data: str) -> dict:
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

    def get_login_data(self, encrypt_data: bytes, username: str, salt: str, iv: str, associated_data: str):
        return {
            'EncryptData': binascii.hexlify(encrypt_data).decode("ascii"),
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
        decCipher = AES.new(key, AES.MODE_CCM, iv)
        decCipher.update(bytes("nonce".encode()))
        decryptData = decCipher.decrypt(bytes.fromhex(login_response['encryptData']))

        return decryptData[:32].decode()

    def restart(self, session: Session, url: str):
        restart_request_data = {"RestartReset": "Restart"}
        session.post(f"{url}/php/ajaxSet_status_restart.php", data=json.dumps(restart_request_data))

class FirmwareEarly2019(Firmware):
    def get_salt_and_iv(self):
        their_salt = re.search(r".*var mySalt = '(.+)';.*", str(self.soup.head))[1]
        their_iv = re.search(r".*var myIv = '(.+)';.*", str(self.soup.head))[1]
        salt = bytes.fromhex(their_salt)
        iv = bytes.fromhex(their_iv)

        return (salt, iv)

    def get_login_data(self, encrypt_data: bytes, username: str, salt: str, iv: str, associated_data: str):
        return {
            'EncryptData': binascii.hexlify(encrypt_data).decode("ascii"),
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
        decCipher = AES.new(key, AES.MODE_CCM, iv)
        decCipher.update(bytes("nonce".encode()))
        decryptData = decCipher.decrypt(bytes.fromhex(login_response['encryptData']))

        return decryptData[:32].decode()

    def restart(self, session: Session, url: str):
        restart_request_data = {"RestartReset": "Restart"}
        session.put(f"{url}/php/ajaxSet_status_restart.php", data=json.dumps(restart_request_data))


class FirmwareMid2018(Firmware):
    def get_salt_and_iv(self):
        salt = os.urandom(8)
        iv = os.urandom(8)
        return (salt, iv)

    def get_login_data(self, encrypt_data: bytes, username: str, salt: str, iv: str, associated_data: str):
        return {
            'EncryptData': binascii.hexlify(encrypt_data).decode("ascii"),
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
        session.put(f"{url}/php/ajaxSet_status_restart.php", data=json.dumps(restart_request_data))
