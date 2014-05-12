from Message import Message
from MessageTypes import messageTypes
from OpenSSL import crypto as ocrypto
from pprint import pprint
from struct import pack

class CertVerifyReq(Message):

    def createFromBytes(self, msgtype, data):
        Message.createFromBytes(self, msgtype, data)
        self.options = unpack(">B", data[0])
        numcerts = unpack(">B", data[1])
        for i in range(0, numcerts):
            # TODO: Not implemented
            pass

    def createFromValues(self, options, certs, hostname, ip, port):
        self.certchain = []
        chainlength = 0
        for cert in certs:
            certobj = ocrypto.load_certificate(ocrypto.FILETYPE_PEM, cert)
            derobj = ocrypto.dump_certificate(ocrypto.FILETYPE_ASN1, certobj)
            chainlength += len(derobj)
            self.certchain.append(derobj)

        Message.createFromValues(self, messageTypes['CERT_VERIFY_REQUEST'], 5 + chainlength + len(hostname) + len(ip) + len(str(port)))
        self.options = options
        self.hostname = hostname
        self.ip = ip
        self.port = port
        
    def getBytes(self):
        certstring = "".join(self.certchain)
        hoststring = "%s|%s|%s" % (self.hostname, self.ip, self.port)
        formatstring = ">BB%ds%ds" % (len(certstring), len(hoststring))
        return pack(formatstring, self.options, len(self.certchain), certstring, hoststring)

if __name__ == "__main__":
    import cbutils.CertUtils
    c = cbutils.CertUtils.get_chain("thenybble.de", 443)
    pprint(c)
    req = CertVerifyReq()
    req.createFromValues(0, c, "thenybble.de", "176.28.10.36", 443)
    b = req.getBytes()
    with open("out.pack", "w") as f:
        f.write(b)
