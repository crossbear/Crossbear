"""
Public IP Notification request for crossbear.

This message is sent to getPublicIp.jsp and contains a AES256 key encrypted
with the server's public RSA key.
"""

from Message import Message

# TODO This class will be renamed to PubIPRequest or something similar

class PipReq(Message):
    def __init__(self, rsadkey=bytes()):
        Message.__init__(self, ("PipReq",), len(rsadkey))
        # rsa encrypted aes key 
        self.rsadkey = rsadkey
        print len(rsadkey)
    def getBytes(self):
        return self.rsadkey
