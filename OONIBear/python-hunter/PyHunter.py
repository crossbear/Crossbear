"""
A crossbear hunter implementation in python.
"""

# NOTE all print commands should log to the ooni thingy.
from   HTLFetcher                 import HTLFetcher
from   cbmessaging.Message        import Message
from   cbmessaging.HTRepNewCert   import HTRepNewCert
from   cbmessaging.HTRepKnownCert import HTRepKnownCert
from   PipFetcher                 import PipFetcher
#from   cbmessaging.CurServTime    import CurServTime
from   time                       import time
from   util.CertChain             import get_chain
from   Crypto.Hash                import SHA256, MD5
from   Tracer                     import Tracer
from   util.SingleTrustHTTPS      import SingleTrustHTTPS
import random
import ssl
import pprint 



class PyHunter(object):
    # TODO: Merge this with the CBTester class
    def __init__(self, cbServerHostName, tracerMHops, tracerSPerHop,
                 cbServerCert):
        
        self.cbServerHostName    = cbServerHostName
        self.tracer              = Tracer(tracerMHops, tracerSPerHop)
        self.hts                 = {"tasks" : [], "pip": {4:{}, 6:{}}}
        self.cbServerCert        = cbServerCert
        self.pipfetcher          = PipFetcher(self.cbServerHostName, self.cbServerCert)
        self.htlfetcher = HTLFetcher(cbServerHostName, 443, self.cbServerCert)

    def getHTL(self):
        """fetchs the hunting task list"""
        htl = self.htlfetcher.fetch()
        for ht in htl:
            if ht.type == Message.types["CurServTime"]:
                self.hts["cs"] = ht
                continue
            elif ht.type == Message.types["PipNot"][4]:
                self.hts["pip"][4]["not"] = ht
                self.hts["pip"][4]["ts"]  = time()
                continue
            elif ht.type == Message.types["PipNot"][6]:
                self.hts["pip"][6]["not"] = ht
                self.hts["pip"][6]["ts"] = time()
                continue
            elif (ht.type == Message.types["Sha256Task"][4] or
                 ht.type == Message.types["Sha256Task"][6]):
                self.hts["tasks"].append(ht)
                continue
        # TODO: Return useful log information
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
        except KeyError:
            return False
        try:
            print "Geting a new Public IP Notification!"
            pipn = self.pipfetcher.getPublicIPN(ipv)
            self.hts["pip"][ipv]["not"] = pipn
            return True
        except Exception:
            return False

    def send_results(self, hts):
        """sends the results to the CB server"""

        conn = SingleTrustHTTPS(self.cbServerCert, self.cbServerHostName, 443)
        conn.request("SEND", "", "".join(h.binary() for h in hts))
        conn.close()

    def executeHT(self,ht):
        """executes a hunting task"""
        ipv = 4 if ht.type == Message.types["Sha256Task"][4] else 6
        if not self.freshen_pip(ipv):
            print ("Skipping execution of task", ht.taskID, "due to the lack",
                    "of fresh PublicIP for it.")
            return
        print "Executing task", ht.taskID, "(", map(lambda x : x.encode("base64"), ht.knownCertHashes), ")"
        chain = get_chain(ht.targetIP,ht.targetPort)
        pprint.pprint(chain)
        h = SHA256.new()
        h.update(ssl.PEM_cert_to_DER_cert(chain[0]))
        scertH = h.hexdigest()

        def md5it(c):
            h = MD5.new()
            h.update(c)
            return h.hexdigest()
        
        #chain = chain[::-1]
        ccmd5 = "".join(map(md5it, chain[1:]))
        print "md5 of chain:", ccmd5

        h = SHA256.new()
        h.update(scertH + ccmd5)
        cccHash = h.digest()

        print "hash of server cert:",cccHash.encode("base64")
        cert_known = any(cHash == cccHash for cHash in ht.knownCertHashes)
        print "Tracerouting!"
        trace      = self.tracer.traceroute(ht.targetIP)

        if cert_known:
            print "Cert Known!"
            return HTRepKnownCert(ht.taskID, ht.hmac, cccHash, trace)
        else:
            print "Cert New!"
            return HTRepNewCert(ht.taskID,
                                self.hts["cs"].currentServTime(),
                                self.hts["pip"][ipv]["not"].hmac,
                                chain,
                                trace)
        print "Done!"
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
    
        
        
        
    
    

    
