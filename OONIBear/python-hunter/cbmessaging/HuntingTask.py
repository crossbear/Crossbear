"""
(a client side) hunting task class for crossbear
"""


from Message import Message
import ipaddr

class HuntingTask(Message):
    def __init__(self, data, ipv):
        # call the super class constructor
        Message.__init__(self, ("Sha256Task", ipv), len(data))
        
        # extract the task id
        pos = 0
        taskID_bytes = data[pos:pos+4]
        self.taskID  = Message.ba2int(taskID_bytes)
        pos += 4
        
        # extract the number of well known certificate chain hashes
        knownCerts = 0xff & Message.ba2int(data[pos], "B")
        pos += 1
        
        # store all the known cert hashes in a list
        self.knownCertHashes = []
        
        for i in range(knownCerts):
            self.knownCertHashes.append(data[pos:pos+32])
            pos += 32
        
        # extract the target ip address
        addrAsInt = Message.ba2int(data[pos:pos+self.ipLen], fmt = "I" if ipv
                == 4 else "L")
        # convert the addr in bytes in to an address string
        if ipv == 4:
            self.targetIP = ipaddr.IPv4Address(addrAsInt)
        else:
            self.targetIP = ipaddr.IPv6Address(addrAsInt)
        print self.targetIP
        pos += self.ipLen

        # extract the port the hunting task's target
        portBytes = data[pos:pos+2]
        # convert the bytes to the corresponding int
        # 2 bytes -> short so the corresponding format string is "h"
        self.targetPort = Message.ba2int(portBytes, "h")
        pos += 2

        # extract the hostname field of the message and cast it to a string
        restBytes = data[pos:]
        self.targetHost = str(restBytes)
