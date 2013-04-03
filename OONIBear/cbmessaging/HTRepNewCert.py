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
    certhash -- hash of the observed certificate chain (byte array, 32B)
    trace -- Traceroute to the alleged victim host (String, variable length)
    """

    # RH: CONTINUE HERE

    def createFromValues(self, taskid, ts, hmac, certchain, trace):
        # set message type and length (72B for taskid, ts, hmac and
        # plus length of traceroute)
        Message.createFromValues(self, messageTypes['TASK_REPLY_NEW_CERT'], 40 + len(trace))
        self.taskid    = taskid
        self.ts        = ts
        self.hmac      = hmac
        self.certchain = certchain
        self.trace     = trace


    def getBytes(self):
        timeStamp = int( self.ts / 1000 )
        # Pack in network byte order
        out = [pack(">II", self.taskid, timeStamp), self.hmac,
               pack(">B", 0xff & len(self.certchain))]
        for cert in self.certchain[:min(255, len(self.certchain))]:
            out.append(ssl.PEM_cert_to_DER_cert(cert))
                      
        out.append(self.trace)
        print "\n"
        print out
        print "\n"
        return "".join(out)
