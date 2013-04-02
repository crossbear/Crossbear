"""
(a client side) hunting task class for crossbear
"""


from Message import Message
from MessageTypes import messageTypes
from cStringIO import StringIO
#import ipaddr
from struct import unpack
import struct
import sys

class HuntingTask(Message):
    def createFromBytes(self, msgtype, data):
        Message.createFromBytes(self, msgtype, data)
        
        # extract the task id
        pos = 0

        (self.taskID,)  = unpack(">I", data[:4])
        pos += 4
        
        # extract the number of well known certificate chain hashes
        # Why 0xff?
        knownCerts = 0xff & unpack(">B", data[4])[0]
        pos += 1
        
        # store all the known cert hashes in a list
        self.knownCertHashes = []
        
        for _ in range(knownCerts):
            # TODO: Unpack those?
            self.knownCertHashes.append(data[pos:pos+32])
            pos += 32
        
        # convert the addr in bytes in to an address string
        if msgtype == messageTypes['IPV4_SHA256_TASK']:
            ipLen = 4
            self.ipVer = 4
        elif msgtype == messageTypes['IPV6_SHA256_TASK']:
            ipLen = 16
            self.ipVer = 6
        self.targetIP = ".".join(str(x) for x in unpack('>' + 'B' * ipLen, data[pos: pos + ipLen]))
        pos += ipLen

        # extract the port of the hunting task's target
        (self.targetPort,) = unpack('>H', data[pos:pos + 2])
        pos += 2
        # The rest is the target host name.
        self.targetHost = data[pos:]

    def getBytes(self):
        out = StringIO()
        out.write(pack(">I", self.taskID))
        out.write(pack(">B", len(self.knownCertHashes)))
        ipsplit = self.targetIP.split(".")
        for h in self.knownCertHashes:
            out.write(h)
        if self.ipVer == 4:
            out.write(pack(">BBBB", *ipsplit))
        elif self.ipVer == 6:
            out.write(pack(">BBBBBBBBBBBBBBBB", *ipsplit))
        out.write(self.targetHost)
        return
