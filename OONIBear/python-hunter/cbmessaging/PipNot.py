"""
a class for public ip notifications of crossbear
"""

__author__ = "Vedat Levi Alev"

# TODO: This class will be renamed to PubIPNotification or something
# similar

from Message import Message
import ipaddr


class PipNot(Message):
    def __init__(self, data, ipv):
        Message.__init__(self, ("PipNot", ipv), len(data))
        self.hmac = data[:32]
        self.publicIP = ipaddr.Bytes(data[32:32+self.ipLen])
