
from Message import Message
from MessageTypes import messageTypes
from struct import unpack,pack
from binascii import hexlify


class SignatureMessage(Message):

    def createFromValues(self, data):
        Message.createFromValues(self, messageTypes["SIGNATURE"], len(data))
        self.data = data
        
    def createFromBytes(self, msgtype, data):
        Message.createFromBytes(self, msgtype, data)
        # Don't unpack, because we need the data in string format.
        self.signature = data

    def getBytes(self):
        return self.signature

    def __repr__(self):
        return "SignatureMessage(signature=%s)" % (hexlify(self.signature),)
