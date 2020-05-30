import nntplib
import rsa
import gkd.crypt as gkd
username = b"tt"
pri = rsa.PrivateKey.load_pkcs1(open("./id_rsa.pem", 'rb').read())
pub = rsa.PublicKey.load_pkcs1(open('./id_rsa.pem.pub', 'rb').read())
known = {username : pub}

enc = gkd.Encrypting(pri, pub, username, gkd.mk_aes())
enc.add_str("excuse me?aaa")

print(gkd.decrypt(enc.get(), known))



class Client:
    nn : nntplib.NNTP
    used_channel : nntplib.GroupInfo

    def __init__(self, url: str, used_channel: str):
        self.nn = nntplib.NNTP(url)
        self.used_channel = self.nn.group(self.used_channel)
        
    @property
    def host(self):
        return self.nn.host
    

    def find_user(self, userid):
        pass

    def find_ari(self, userid):
        pass
