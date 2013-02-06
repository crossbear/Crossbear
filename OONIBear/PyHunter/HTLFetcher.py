"""
HuntingTask List fetcher for crossbear implemented in python.
The hash of the server certificate needs to be a sha256 hash
"""

__author__ = "Vedat Levi Alev"

from cbmessaging.Message import Message
from cbmessaging.HuntingTask import HuntingTask
from cbutils.SingleTrustHTTPS   import SingleTrustHTTPS
from Crypto.Hash import SHA256
from cbmessaging.PipNot  import PipNot
from cbmessaging.CurServTime import CurServTime

class HTLFetcher(object):

    hts = {"PipNot" : PipNot, "CurServTime" : CurServTime,
        "Sha256Task" : HuntingTask}



    def __init__(self, servHost, servPort, servCert):
        self.servHost     = servHost
        self.servPort     = servPort
        self.servCert     = servCert



    @staticmethod
    def extractNext(resp):
        """
        Extract the messages in a Hunting Task List sent
        by the Crossbear server.
        """

        try:
            msgType = Message.ba2int(resp.read(1), "B")
        except Exception:
            # TODO: Yikes. Return something meaningful.
            return

        # TODO: comment this
        trace = None

        # FIXME: we abuse the structure of Message.type 
        # (dictionary with the depth 2) by 
        # performing a depth first search on it. as the depth is bounded by
        # two, two explicit loops should suffice. this might be problematic,
        # if the need occurs to extend the message class
        for key in Message.types:
            if type(Message.types[key]) != type({}):
                if Message.types[key] == msgType:
                    trace = (key,)
                    break
            else:
                for keyj in Message.types[key]:
                    if Message.types[key][keyj] == msgType:
                        trace = (key,keyj)
                        break
            if trace != None:
                break
        if not HTLFetcher.hts.has_key(trace[0]):
            raise ValueError, "Message type %d not expected." % msgType
        # Now that we know this is in fact a crossbear hunting task, we read
        # its length (it is a short so the corresponding format string is "h")
        msgLen = Message.ba2int(resp.read(2), "h")
        # we read 3 bytes so far, so the raw data consists of msgLen - 3 bytes
        data = resp.read(msgLen - 3)
        # FIXME: this is a bit hackish, nevertheless i still find it
        # to be better than the original java implementation.
        if len(trace) == 1:
            args = (data,)
        else:
            args = (data, trace[1])
        # TODO: make this easier - I don't get it
        return HTLFetcher.hts[trace[0]](*args)



    def fetch(self):
        """
        Fetch the current list of Hunting Tasks from the Crossbear
        server. To this end, connect via TLS and verify if the
        received server certificate is the one we have stored for
        Crossbear.
        """
        # Open HTTPs connection to Crossbear server
        conn = SingleTrustHTTPS(self.servCert, self.servHost,  self.servPort)
        
        # Now request the current hunting task list
        conn.request("GET", "/getHuntingTaskList.jsp")
        resp = conn.getresponse()

        # Extract "messages" in reply
        # TODO: are these really messages?
        huntingTasks = []

        # TODO ARGH replace this loop
        # Make extractNext return None or something iterable
        while 1:
            next = HTLFetcher.extractNext(resp)
            if next:
                huntingTasks.append(next)
            else:
                resp.close()
                break
        return huntingTasks
