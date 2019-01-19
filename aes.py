#!/usr/bin/env python3
#
# Python3 AES encryption compatible with openssl
#
# encrypt with openssl:
# $ echo -n "hello world" | openssl enc -e -aes-256-cbc -base64 -md sha256 -k password -p
# salt = 2C8A40BAAA94F403
# key  = 48345D2343D99187EC0F9DC28B5C27F1D71839BDDFBC639CE4EAD2E48360CB71
# iv   = 7CD3A32D9C4BA2B4B8F03A105B3F95A5
# U2FsdGVkX18sikC6qpT0A4smic6o30MeBljBP5+SyTg=
#
# decrypt with openssl:
# echo "U2FsdGVkX18sikC6qpT0A4smic6o30MeBljBP5+SyTg=" | openssl enc -d -aes-256-cbc -base64 -md sha256 -k password

import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
import subprocess

class AESCipher(object):

    def __init__(self, password, verbose=False):
        self.password = password 
        self.verbose = verbose
 
    def encrypt(self, text):
        salt     = Random.new().read(8)
        key, iv  = self.openssl_key_and_iv(self.password, salt)        
        cipher   = AES.new(key, AES.MODE_CBC, iv)
        enc      = b'Salted__' + salt + cipher.encrypt(self.pad(text))
        enc      = base64.b64encode(enc).decode('utf-8')
        if self.verbose:
            print(f'text        : { text }')
            print(f'salt        : { salt.hex().upper() }')
            print(f'key         : { key.hex().upper() }')
            print(f'iv          : { iv.hex().upper() }')
            print(f'enc         : { enc }')
        return enc

    def decrypt(self, enc):
        enc     = base64.b64decode(enc)
        salt    = enc[:16][len('Salted__'):]   
        key, iv = self.openssl_key_and_iv(self.password, salt)
        cipher  = AES.new(key, AES.MODE_CBC, iv)
        text    = self.unpad(cipher.decrypt(enc[16:])).decode('utf-8')
        if self.verbose:
            print(f'enc         : { enc }')
            print(f'salt        : { salt.hex().upper() }')
            print(f'key         : { key.hex().upper() }')
            print(f'iv          : { iv.hex().upper() }')
            print(f'text        : { text }')
        return text

    @staticmethod
    def openssl_key_and_iv(password, salt):
        key_length = 32
        iv_length = 16
        d = d_i = b''
        while len(d) < key_length + iv_length:
            d_i = hashlib.sha256(d_i + password.encode() + salt).digest()
            d += d_i
        return d[:key_length], d[key_length:key_length + iv_length]

    @staticmethod
    def pad(s):
        return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)

    @staticmethod
    def unpad(s):
        return s[:-ord(s[len(s)-1:])]


def test(verbose = False):
    text = 'hello world'
    password = 'password'

    a = AESCipher(password, verbose=verbose)
    
    # encrypt and decrypt with python
    pyenc = a.encrypt(text)
    pydec = a.decrypt(pyenc)
    assert text == pydec

    # encrypt and decrypt with openssl
    openc = subprocess.run(f'echo -n "{text}" | openssl enc -e -aes-256-cbc -base64 -md sha256 -k {password}',
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8').stdout
    opdec = subprocess.run(f'echo "{openc}" | openssl enc -d -aes-256-cbc -base64 -md sha256 -k {password}',
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8').stdout
    assert text == opdec

    # encrypt with python and decrypt with openssl
    pyenc = a.encrypt(text)
    opdec = subprocess.run(f'echo "{pyenc}" | openssl enc -d -aes-256-cbc -base64 -md sha256 -k {password}',
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8').stdout
    assert text == opdec

    # encrypt with openssl and decrypt with python
    openc = subprocess.run(f'echo -n "{text}" | openssl enc -e -aes-256-cbc -base64 -md sha256 -k {password}',
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8').stdout
    pydec = a.decrypt(pyenc)
    assert text == pydec
        


if __name__ == '__main__':

    import sys
    verbose = len(sys.argv) > 1 and sys.argv[1] == '-v'
    test(verbose)
    