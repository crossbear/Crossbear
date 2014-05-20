"""
A crossbear hunter implementation in python.
"""

# NOTE all print commands should log to the ooni thingy.
from   HTLFetcher                 import HTLFetcher
from   cbmessaging.Message        import Message
from   cbmessaging.MessageList    import MessageList
from   cbmessaging.MessageTypes   import messageTypes, messageNames
from   cbmessaging.HTRepNewCert   import HTRepNewCert
from   cbmessaging.HTRepKnownCert import HTRepKnownCert
from   PipFetcher                 import PipFetcher
#from   cbmessaging.CurServTime    import CurServTime
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


display = lambda l : map(lambda z: binascii.hexlify(z), l)

class PyHunter(object):
    # TODO: Merge this with the CBTester class
    def __init__(self, cbServerHostName, cbServerCert, tracerMHops, tracerSPerHop, tracerPeriod):

        self.cbServerHostName    = cbServerHostName
        self.tracer              = Tracer(tracerMHops, tracerSPerHop, tracerPeriod)
        self.hts                 = {"tasks" : [], "pip": {4:{}, 6:{}}}
        self.cbServerCert        = cbServerCert
        self.pipfetcher          = PipFetcher(self.cbServerHostName, self.cbServerCert)
        self.htlfetcher          = HTLFetcher(cbServerHostName, 443, self.cbServerCert)

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
                self.hts["pip"][6]["not"] = msg
                self.hts["pip"][6]["ts"] = time()
                continue
            elif msg.type == messageTypes["IPV4_SHA256_TASK"] or msg.type == messageTypes["IPV6_SHA256_TASK"]:
                self.hts["tasks"].append(msg)
                continue
        return {}
        
    def freshen_pip(self,ipv):
        """
        checks whether the current pip is fresh
        pulls a fresh one if that isn't the case
        """
        validity = 60000
        try:
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

    def send_result(self, ht):
        """sends the results to the CB server"""
        conn = SingleTrustHTTPS(self.cbServerCert, self.cbServerHostName, 443)
        conn.request("POST", "/reportHTResults.jsp",
                     MessageList.getBytesForMessage(ht))
        response = conn.getresponse()
        if response.status != 200:
            print "Error submitting hunting task results. Error code: %s, %s" % (response.status, response.reason)
        conn.close()

    def executeHT(self,ht):
        """executes a hunting task"""
        ipv = 4 if ht.type == messageTypes["IPV4_SHA256_TASK"] else 6

        # TODO get this to the report
        if not self.freshen_pip(ipv):
            print "Skipping execution of task", ht.taskID, "due to the lack",\
                    "of fresh PublicIP for it."
            return None

        # TODO get this to the report      
        chain = get_chain(ht.targetIP,ht.targetPort)
            
        
        witness  = None
        if ht.knownCertHashes:

            ht.cccHashs = compute_chain_hashes(chain)
            #print "Possible hashes are", display(ht.cccHashs)


            for cHash in ht.cccHashs:
                if any(sHash == cHash for sHash in ht.knownCertHashes):
                    witness = cHash
                    break

        # TODO get this to report
        #print "Tracerouting!"
        trace = self.tracer.traceroute(self.hts["pip"][ipv]["not"].publicIPString, ht.targetIP)
        if witness:
            # TODO get this to report
            rep = HTRepKnownCert()
            rep.createFromValues(ht.taskID,
                                 self.hts["pip"][ipv]["not"].hmac,
                                 witness,
                                 trace)
        
        else:
            # TODO get this to report
            rep = HTRepNewCert()
            rep.createFromValues(ht.taskID,
                                self.hts["cs"].currentServTime(),
                                self.hts["pip"][ipv]["not"].hmac,
                                chain,
                                trace)
        return rep
        
    def executeHTL(self):
        nr     = 0
        report = {}
        random.shuffle(self.hts["tasks"])
        
        for ht in self.hts["tasks"]:

            print "---"
            print "Executing task", ht.taskID
            print "IP Address and Port", ht.targetIP, ht.targetPort
            print "Target host name is", ht.targetHost
            # print "The known hashes are", display(ht.knownCertHashes)
            try:
                rep = self.executeHT(ht)
            except IOError as e:
                print "IO Error occurred when executing HT: " + str(e)
                rep = False
            
            report[ht.taskID]                    = {}            
            report[ht.taskID]['known hashes']    = display(ht.knownCertHashes)
            report[ht.taskID]['target ip']       = ht.targetIP
            report[ht.taskID]['target port']     = ht.targetPort
            report[ht.taskID]['target host']     = ht.targetHost
            report[ht.taskID]['possible hashes'] = display(ht.cccHashs)
            
            if rep:
                print "Hunting task result",  messageNames[rep.type]
                report[ht.taskID]['reply type'] = messageNames[rep.type]
                report[ht.taskID]['trace'] = rep.trace
                self.send_result(rep)
            else:
                print "Hunting task result Nil"
                report[ht.taskID]['reply type'] = 'Nil'
        # TODO: Return useful log information
        
        return report
        
