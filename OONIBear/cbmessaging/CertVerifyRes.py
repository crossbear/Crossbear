from Message import Message
from MessageTypes import messageTypes
from OpenSSL import crypto as ocrypto
from pprint import pprint
from struct import pack,unpack

class CertVerifyRes(Message):

    def createFromBytes(self, msgtype, data):
        Message.createFromBytes(self, msgtype, data)
        self.rating = unpack(">B", data[0])[0]
        strlen = len(data) - 1
        formatstring = ">%ds" % (strlen,)
        self.judgement = unpack(formatstring, data[1:])[0]
        self.judgement = self.judgement.split("\n")

    def createFromValues(self, rating, judgement):
        self.rating = rating
        self.judgement = judgement
        Message.createFromValues(self, messageTypes['CERT_VERIFY_RESULT'], 1 + sum([len(x) for x in self.judgement]))
        

    def getBytes(self):
        judgementstring = "\n".join(self.judgement)
        formatstring = ">B%ds" % (len(judgementstring),)
        return pack(formatstring, self.rating, judgementstring)

    def __repr__(self):
        return "CertVerifyRes(judgement=%s, rating=%d)" % (self.judgement, self.rating)

if __name__ == "__main__":
    msg = CertVerifyRes()
    msg.createFromValues(255, ["Dies ist ein", "Test"])
    with open("out.pack", "w") as f:
        f.write(msg.getBytes())
