from bs4 import BeautifulSoup
import re
import binascii
from Crypto.Cipher import AES
import os


def get_firmware_handler(soup: BeautifulSoup):
    if bool(re.search("01.01.117.01.EURO", soup.head.text)):
        print("Auto-detected firmware version 01.01.117.01.EURO")
        return FirmwareMid2018(soup)
    else:
        print("Auto-detected firmware version 01.02.037.03.12.EURO.SIP")
        return FirmwareEarly2019(soup)


class Firmware():
    def __init__(self, soup: BeautifulSoup):
        self.soup = soup

    def get_salt_and_iv(self) -> tuple:
        pass

    def get_login_data(self, encrypt_data: bytes, username: str, salt: str, iv: str, associated_data: str) -> dict:
        pass

    def get_csrf_nonce(self, login_response, key: bytes, iv: str):
        pass


class FirmwareEarly2019(Firmware):
    def get_salt_and_iv(self):
        their_salt = re.search(r".*var mySalt = '(.+)';.*", self.soup.head.text)[1]
        their_iv = re.search(r".*var myIv = '(.+)';.*", self.soup.head.text)[1]
        salt = bytes.fromhex(their_salt)
        iv = bytes.fromhex(their_iv)

        return (salt, iv)

    def get_login_data(self, encrypt_data: bytes, username: str, salt: str, iv: str, associated_data: str):
        return {
            'EncryptData': binascii.hexlify(encrypt_data).decode("ascii"),
            'Name': username,
            'AuthData': associated_data
        }

    def get_csrf_nonce(self, login_response, key: bytes, iv: str):
        decCipher = AES.new(key, AES.MODE_CCM, iv)
        decCipher.update(bytes("nonce".encode()))
        decryptData = decCipher.decrypt(bytes.fromhex(login_response['encryptData']))

        return decryptData[:32].decode()


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

    def get_csrf_nonce(self, login_response, key: bytes, iv: str):
        return login_response['nonce']
