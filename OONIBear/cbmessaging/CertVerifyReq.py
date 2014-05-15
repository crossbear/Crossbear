from Message import Message
from MessageTypes import messageTypes
import ssl
from pprint import pprint
from struct import pack, unpack

class CertVerifyReq(Message):

    def createFromBytes(self, msgtype, data):
        Message.createFromBytes(self, msgtype, data)
        self.options = unpack(">B", data[0])[0]
        numcerts = unpack(">B", data[1])[0]
        for i in range(0, numcerts):
            # TODO: Not implemented
            pass

    def createFromValues(self, options, certs, hostname, ip, port):
        self.certchain = []
        chainlength = 0
        for cert in certs:
            derobj = ssl.PEM_cert_to_DER_cert(cert)
            chainlength += len(derobj)
            self.certchain.append(derobj)

        Message.createFromValues(self, messageTypes['CERT_VERIFY_REQUEST'], 4 + chainlength + len(hostname) + len(ip) + len(str(port)))
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
    import cbmessaging.MessageList
    from cbutils.SingleTrustHTTPS import SingleTrustHTTPS
    c = cbutils.CertUtils.get_chain("www.google.de", 443)
    req = CertVerifyReq()
    req.createFromValues(0, c, "www.google.de", "173.194.44.56", 443)
    print(len(c))
    b = cbmessaging.MessageList.MessageList.getBytesForMessage(req)
    with open("message.bin", "w") as f:
        f.write(b)
    conn = SingleTrustHTTPS("../cbserver.crt", "crossbear.net.in.tum.de", 443)
    conn.request("POST", "/verifyCert.jsp", b)
    response = conn.getresponse()
    content = response.read()
    ml = cbmessaging.MessageList.MessageList(content)
    for msg in ml.allMessages():
        print msg.type_name
