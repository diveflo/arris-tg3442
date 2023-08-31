import binascii
import json
import os
import re

from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from requests.sessions import Session


def get_firmware_handler(soup: BeautifulSoup):
    firmware_versions = {
        "01.01.117.01.EURO": FirmwareMid2018,
        "01.02.037.03.12.EURO.SIP": FirmwareEarly2019,
        "01.02.068.10.EURO.SIP": FirmwareMid2020,
        "01.02.068.11.EURO.PC20": FirmwareMid2020,
        "01.02.068.13.EURO.PC20": FirmwareMid2021,
        "01.04.046.07.EURO.PC20": FirmwareEnd2021,
        "01.04.046.12.EURO.PC20": FirmwareEnd2021,
        "01.04.046.15.EURO.PC20": FirmwareEarly2022,
        "01.04.046.17.EURO.PC20": FirmwareMid2022,
        "01.04.046.25.EURO.PC20": FirmwareEnd2022
    }

    firmware_text = str(soup.head)
    for version, firmware_class in firmware_versions.items():
        if re.search(version, firmware_text):
            print(f"Auto-detected firmware version {version}")
            return firmware_class(soup)

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

    def get_phone_log(self, session: Session, url: str):
        response = session.get(url + "/php/phone_call_log_data.php?_n=73995&{%22PhoneLogRecord%22:{}}")
        if not response.ok:
            response.raise_for_status()
        else:
            return json.loads(response.content)


class FirmwareMid2021(FirmwareMid2020):
    pass


class FirmwareEnd2021(FirmwareMid2021):
    pass


class FirmwareEarly2022(FirmwareEnd2021):
    pass

class FirmwareMid2022(FirmwareEarly2022):
    pass

class FirmwareEnd2022(FirmwareMid2022):
    pass


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
