import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

class AESCipher(object):

    def __init__(self, key): 
        self.bs = 16 
        self.key_hash = hashlib.sha256(key.encode())
        self.key = self.key_hash.digest()
        # print(f'key: {self.key}\nhex: { self.key_hash.hexdigest() }\nsize: { self.key_hash.digest_size }')

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)).decode('utf-8')

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    def _unpad(self, s):
        return s[:-ord(s[len(s)-1:])]

def test():
    a = AESCipher('password')
    msg = 'hello world'
    enc = a.encrypt(msg)
    dec = a.decrypt(enc)
    print(msg)
    print(enc)
    print(dec)
    assert msg == dec

if __name__ == '__main__':
    test()
