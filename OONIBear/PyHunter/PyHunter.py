"""
A crossbear hunter implementation in python.
"""

# NOTE all print commands should log to the ooni thingy.
from   HTLFetcher                 import HTLFetcher
from   cbmessaging.Message        import Message
from   cbmessaging.MessageTypes   import messageTypes
from   cbmessaging.HTRepNewCert   import HTRepNewCert
from   cbmessaging.HTRepKnownCert import HTRepKnownCert
from   PipFetcher                 import PipFetcher
from   time                       import time
from   cbutils.SingleTrustHTTPS   import SingleTrustHTTPS
from   cbutils.CertUtils import get_chain, compute_chain_hashes
from   Crypto.Hash                import SHA256, MD5
from   Tracer                     import Tracer
import random
import ssl
import pprint 
import traceback
import binascii


from itertools import permutations

class PyHunter(object):
    # TODO: Merge this with the CBTester class
    def __init__(self, cbServerHostName, cbServerCert, tracerMHops, tracerSPerHop):

        self.cbServerHostName    = cbServerHostName
        self.tracer              = Tracer(tracerMHops, tracerSPerHop)
        self.hts                 = {"tasks" : [], "pip": {4:{}, 6:{}}}
        self.cbServerCert        = cbServerCert
        self.pipfetcher          = PipFetcher(self.cbServerHostName, self.cbServerCert)
        self.htlfetcher = HTLFetcher(cbServerHostName, 443, self.cbServerCert)

    def getHTL(self):
        """fetchs the hunting task list"""
        ml = self.htlfetcher.fetch()
        for msg in ml.allMessages():
            if msg.type == messageTypes["CURRENT_SERVER_TIME"]:
                self.hts["cs"] = msg
                continue
            elif msg.type == messageTypes["PUBLIC_IP_NOTIF4"]:
                self.hts["pip"][4]["not"] = msg
                self.hts["pip"][4]["ts"]  = time()
                continue
            elif msg.type == messageTypes["PUBLIC_IP_NOTIF6"]:
                print 'bum'
                self.hts["pip"][6]["not"] = msg
                self.hts["pip"][6]["ts"] = time()
                continue
            elif msg.type == messageTypes["IPV4_SHA256_TASK"] or msg.type == messageTypes["IPV6_SHA256_TASK"]:
                self.hts["tasks"].append(msg)
                continue
        # TODO: Return useful log information
        pprint.pprint(self.hts)
        return {}
        
    def freshen_pip(self,ipv):
        """
        checks whether the current pip is fresh
        pulls a fresh one if that isn't the case
        """
        validity = 60000
        try:
	    print "---"
            print "IP Version", ipv
            if (time() - self.hts["pip"][ipv]["ts"] < validity):
                return True
        except KeyError, e:
	    print e
            return False
        try:
            print "Getting a new Public IP Notification!"
            pipn = self.pipfetcher.getPublicIPN(ipv)
            self.hts["pip"][ipv]["not"] = pipn
            return True
        except Exception, e:
	    print e
            return False

    def send_results(self, hts):
        """sends the results to the CB server"""

        conn = SingleTrustHTTPS(self.cbServerCert, self.cbServerHostName, 443)
        conn.request("SEND", "", "".join(h.getBytes() for h in hts))
        conn.close()

    def executeHT(self,ht):
        """executes a hunting task"""
        ipv = 4 if ht.type == messageTypes["IPV4_SHA256_TASK"] else 6

        # TODO get this to the report
        if not self.freshen_pip(ipv):
            print ("Skipping execution of task", ht.taskID, "due to the lack",
                    "of fresh PublicIP for it.")
            return

        # TODO get this to the report
        print "Executing task", ht.taskID
        display = lambda l : map(lambda z: binascii.hexlify(z), l)
        print "The known hashes are", display(ht.knownCertHashes)

        print "IP Address and Port", ht.targetIP, ht.targetPort
        print "Target host name is", ht.targetHost
        
        
        chain = get_chain(ht.targetIP,ht.targetPort)
        
        
        witness = None
        if ht.knownCertHashes:

            cccHashs = compute_chain_hashes(chain)
            print "Possible hashes are", pprint.pprint(cccHashs)


            # TODO get this to report
            # print "hash of server cert:", cccHash.encode("base64")


            for cHash in cccHashs:
                if any(sHash == cHash for sHash in ht.knownCertHashes):
                    witness = cHash
                    break

        # TODO get this to report
        print "Tracerouting!"
        self.tracer.traceroute(ht.targetIP)

        if witness:
            # TODO get this to report
            print "Cert Known!"
            rep = HTRepKnownCert()
            # TODO: I don't know if the selection of the hmac is correct.
            # Previously, it was ht.hmac, but that never existed AFAIK
            rep.createFromValues(ht.taskID,
                                 self.hts["pip"][ipv]["not"].hmac,
                                 witness,
                                 trace)
            return rep
        
        else:
            # TODO get this to report
            print "Cert New!"
            rep = HTRepNewCert()
            rep.createFromValues(ht.taskID,
                                self.hts["cs"].currentServTime(),
                                self.hts["pip"][ipv]["not"].hmac,
                                chain,
                                trace)
            return rep
        
    def executeHTL(self):
        nr = 0
        htr = []
        random.shuffle(self.hts["tasks"])
        
        for r in self.hts["tasks"]:
            
            rep = self.executeHT(r)

            if rep:
                htr.append(rep)
                nr += 1
                
            if nr >= 5:
                self.send_results(htr)
                nr = 0
                htr = []
                
        if htr:
            self.send_results(htr)
        # TODO: Return useful log information
        return {}
        
