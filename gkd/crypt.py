import secrets
import pyaes
import rsa
import zlib

sepbit = 6
def mk_aes(sepbit=sepbit):
    key = bytes([secrets.randbits(sepbit) for _ in range(32)])
    return key

def get_pwd_head_n(pub: rsa.PublicKey):
    return rsa.common.byte_size(pub.n)

class Encrypting:
    def __init__(self, pri: rsa.PrivateKey, pub:rsa.PublicKey, username: bytes, aes_key: bytes):
        self.pri = pri
        self.username = username  # nickname<email@host>
        self.key = aes_key
        self.aes = pyaes.AESModeOfOperationCTR(aes_key)
        data = self.data = bytearray()

        # data format
        # uncompressed:
        # |username: ...|0| -- not encrypted, used for searching public key
        # compressed:
        # |nPUB|AES_KEY(encrypted by RSA)|contents encrypted by AES|
        n = get_pwd_head_n(pub)
        data.extend(n.to_bytes(4, 'little'))
        self.data.extend(rsa.encrypt(self.key, self.pri))

    def add_str(self, msg: str):
        msg = msg.encode('utf8')
        self.data.extend(self.aes.encrypt(msg))

    def add_bytes(self, msg: bytes):
        self.data.extend(self.aes.encrypt(msg))
    
    def get(self):
        return self.username + bytes([0]) + zlib.compress(self.data, 9)

def decrypt(crypto: bytes, known_users: dict):
    i = crypto.find(0) # TODO: maybe
    username = crypto[:i]
    user_pub: rsa.PublicKey = known_users[username] # TODO: maybe
    crypto = zlib.decompress(crypto[i+1:])
    n = int.from_bytes(crypto[:4], 'little')
    end = 4 + n
    aes_key = rsa.decrypt(crypto[4:end], user_pub)
    aes = pyaes.AESModeOfOperationCTR(aes_key)
    return aes.decrypt(crypto[end:])