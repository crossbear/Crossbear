"""
A client side implementation of the Crossbear Hunting Task Reply that
the client sends if the certificate chain in question is already known
by the Crossbear server. In this case, it is sufficient to send only
the hash value instead of the full certificate chain.
"""

from Message import Message
from struct  import pack


class HTRepKnownCert(Message):
    """
    Representation of a Hunting Trask Reply Known Cert message.

    Arguments:
    taskid -- ID of the Hunting Task (byte array, 4B)
    ts -- server's timestamp of "time-of-execution (byte array, 4B, also see CurServTime.py)
    hmac -- the HMAC token from a Public IP Notification (byte array, 32B)
    certhash -- hash of the observed certificate chain (byte array, 32B)
    trace -- Traceroute to the alleged victim host (String, variable length)
    """
    def __init__(self, taskid, ts, hmac, certhash, trace):
        # set message type and length (72B for taskid, ts, hmac and
        # certhash plus length of traceroute)

        # TODO: we should check for malformed messages, i.e. correct
        # length checks of the input - is this done somewhere else?
        Message.__init__(self, ("CertRep", "Known"), 72 + len(trace))
        self.taskid = taskid
        self.ts     = ts
        self.hmac   = hmac
        self.certhash = certhash
        self.trace  = trace


    def getBytes(self):
        """
        Translates the python object in to an equivalent byte string
        to be transported over the network. Uses the struct module to
        get C strings.
        """
        # We need to divide by 1000 to obtain the results in seconds
        # (the server likes to keep timestamps in ms)
        timeStamp = int(self.ts / 1000)
        out = [pack("II", self.taskid, timeStamp), self.hmac, self.certhash,
               self.trace]
                #pack("%dc" % len(trace), *list(trace))]
        # Concatenate the strings (no delimiter) and return the result
        return "".join(out)