
from Message import Message
from struct import unpack,pack


class SignatureMessage(Message):

    def createFromBytes(self, msgtype, data):
        Message.createFromBytes(self, msgtype, data)
        # Don't unpack, because we need the data in string format.
        self.signature = data

    def getBytes(self):
        return self.signature
