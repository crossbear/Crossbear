"""
Public IP Notification request for crossbear.

This message is sent to getPublicIp.jsp and contains a AES256 key encrypted
with the server's public RSA key.
"""

from Message import Message

# TODO This class will be renamed to PubIPRequest or something similar

class PipReq(Message):
    def __init__(self, key):
        self.rsadkey = key
    
    def createFromBytes_(self, msgtype, content):
        Message.createFromBytes(self, msgtype, content)
        # rsa encrypted aes key 
        # TODO: Decode this?
        self.rsadkey = content
        
    def getBytes(self):
        return self.rsadkey
