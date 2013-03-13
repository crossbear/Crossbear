"""
a class for public ip notifications of crossbear
"""

__author__ = "Vedat Levi Alev"

# TODO: This class will be renamed to PubIPNotification or something
# similar

from Message import Message
import MessageTypes
from struct import unpack, pack
import abc

class PipNot(Message):

    def __init__(self, hmac, publicIP):
        self.publicIP = publicIP
        if len(publicIP) == 16:
            self.ipversion = 6
        elif len(publicIP) == 4:
            self.ipversion = 4
        self.hmac = hmac
    
    def createFromBytes(self, msgtype, data):
        Message.createFromBytes(self, msgtype, data)
        self.hmac = unpack(">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", data[:32])
        if msgtype == MessageTypes.messageTypes['PUBLIC_IP_NOTIF4']:
            ipLen = 4
            self.ipversion = 4
        elif msgtype == MessageTypes.messageTypes['PUBLIC_IP_NOTIF6']:
            ipLen = 16
            self.ipversion = 6
        self.publicIP = unpack(">" + "B" * ipLen, data[32:32 + ipLen])


    def getBytes(self):
        bytes = ""
        bytes += pack(">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", *self.hmac);
        if self.ipversion == 4:
            bytes += pack(">BBBB", *self.publicIP)
        elif self.ipversion == 6:
            bytes += pack(">BBBBBBBBBBBBBBBB", *self.publicIP)
        return bytes
