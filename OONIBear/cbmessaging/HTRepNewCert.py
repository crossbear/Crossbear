"""
A client side implementation of the Crossbear Hunting Task Reply that
the client sends if the certificate chain in question is not known to
the Crossbear server. In this case, it is must end the full
certificate chain to the Crossbear server.

Structure:
    Header
    Task ID (4b)
    Server time of execution (4b)
    hmac of the ip that was inserted in the trace to the server as first hop
    (32b)
    length of the certificate chain that was observed by the client (1b)
    certificate chain (var. length)
    trace to the target (var. length)
"""

from Message import Message
from MessageTypes import messageTypes
from struct  import pack
import ssl
class HTRepNewCert(Message):
    """
    Representation of a Hunting Trask Reply Known Cert message.

    Arguments:
    taskid -- ID of the Hunting Task (byte array, 4B)
    ts -- server's timestamp of "time-of-execution (byte array, 4B, also see CurServTime.py)
    hmac -- the HMAC token from a Public IP Notification (byte array, 32B)
    certchain -- The observed certificate chain (byte array, variable length)
    trace -- Traceroute to the alleged victim host (String, variable length)
    """

    # RH: CONTINUE HERE

    def createFromValues(self, taskid, ts, hmac, certchain, trace):
        # Convert certs to DER
        self.certchain = []
        for cert in certchain[:min(255,len(certchain))]:
            self.certchain.append(ssl.PEM_cert_to_DER_cert(cert))
        certlength = sum(len(x) for x in self.certchain)
        # set message type and length ( 41 Bytes for taskid, ts, hmac and number of certificates
        # plus length of trace and length of cert chain.
        Message.createFromValues(self, messageTypes['TASK_REPLY_NEW_CERT'], 41 + len(trace) + certlength)
        self.taskid    = taskid
        self.ts        = ts
        self.hmac      = hmac
        self.trace     = trace


    def getBytes(self):
        # Pack in network byte order
        out = [pack(">II", self.taskid, int(self.ts)), self.hmac,
               pack(">B", 0xff & len(self.certchain))]
        out.append("".join(self.certchain))
        out.append(self.trace)
        result = "".join(out)
        return result
