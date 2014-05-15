''' A recode of the Message class with hopefully better message parsing.'''

from struct import pack, unpack
import PipNot, PipReq, CurServTime, SignatureMessage, HuntingTask, HTRepNewCert, HTRepKnownCert, CertVerifyReq, CertVerifyRes

import cStringIO
import types
from Message import Message

class MessageList(object):

    messageClasses = { 0: PipNot.PipNot, 1: PipNot.PipNot, 2: PipReq.PipReq, 5: CurServTime.CurServTime, 6: SignatureMessage.SignatureMessage, 10: HuntingTask.HuntingTask, 11: HuntingTask.HuntingTask, 20: HTRepNewCert.HTRepNewCert, 21: HTRepKnownCert.HTRepKnownCert, 100: CertVerifyReq.CertVerifyReq, 110: CertVerifyRes.CertVerifyRes }
    
    # A HTTPResponse object.
    def __init__(self, response):
        self.messages = self.parseResponse(response)

    def parseResponse(self, body):
        leftover = len(body)
        stream = cStringIO.StringIO(body)
        result = []
        while leftover > 0:
            (msgtype, length) = unpack(">BH", stream.read(3))
            leftover -= length
            clazz = self.messageClasses[msgtype]
            # Substract three for the header which we have already
            # read.  Pass data in undecoded form, because we won't
            # always need bytes, and decoding from a string is more
            # convenient than reassembling the bytes.
            instance = clazz()
            instance.createFromBytes(msgtype, stream.read(length - 3))
            result.append(instance)
        return result

    def getMessage(self, index):
        return self.messages[index]

    def removeMessage(self, index):
        del(self.messages[index])

    def getBytes(self):
        result = ""
        for msg in self.messages:
            result += msg.data
        return result
    
    def allMessages(self):
        return self.messages

    def getBytes(self):
        return "".join([MessageList.getBytesForMessage(x) for x in self.messages ])

    @staticmethod
    def getBytesForMessage(msg):
        out = cStringIO.StringIO()
        out.write(pack(">B", msg.type))
        out.write(pack(">H", msg.length))
        out.write(msg.getBytes())
        ret = out.getvalue()
        out.close()
        return ret

    def length(self):
        return len(self.messages)

import urllib
from pprint import pprint
if __name__ == '__main__':
    conn = urllib.urlopen("https://cefalu.net.in.tum.de/getHuntingTaskList.jsp")
    body = conn.read()
    with open("/home/jeeger/tmp/htl-server","w") as f:
        f.write(body)
    l = MessageList(body)
    pprint(l.getMessage(3).__dict__)
    with open("/home/jeeger/tmp/htl-client","w") as f:
        f.write(l.getBytes())
