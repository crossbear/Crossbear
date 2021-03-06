"""
A Public IP Notification fetcher for Crossbear PyHunter.
"""

__author__ = "Vedat Levi Alev"

import dns.rdtypes.IN.A
import dns.rdtypes.IN.AAAA

from dns                     import resolver
from Crypto.PublicKey        import RSA
from Crypto.Cipher           import PKCS1_OAEP
from Crypto.Cipher           import AES
from Crypto.Random           import _UserFriendlyRNG as RNG
from Crypto.Hash             import SHA256
from cbutils.PKCS7           import PKCS7
from cbutils.X509toPubKey    import extractPubKey
from cbmessaging.Message     import Message
from cbmessaging.MessageList import MessageList
from cbmessaging.PipReq      import PipReq
from cbmessaging.PipNot      import PipNot
import requests

class PipFetcher(object):
    """
    Class to fetch a new Public IP notification.
    
    Arguments:
    cbServerHost -- Crossbear server host name (string)
    cbServerCert -- path to file that holds Crossbear server certificate  (string)
    """

    def __init__(self, cbServerHost, cbServerCert):
        self.cbServerCert = cbServerCert
        self.cbServerHost = cbServerHost
        # Rename sip to something understandable, e.g. serverIP
        self.serverIPv4 = None
        self.serverIPv6 = None
        try:
            with open(self.cbServerCert, "r") as cf:
                cert = cf.read()
                # TODO: According to the docs, importKey() should be
                # able to read both DER and PEM - do we really need to
                # call extractPubKey?
                self.pkey   = RSA.importKey(extractPubKey(cert))
        except IOError as e:
            print "Couldn't open certificate:", self.cbServerCert
            raise e
        # look up and set IP addresses of Crossbear server
        # TODO: I guess we need to think about hard-coding these?
        # For auth, the cert is enough, though.
        self.getServerIPs(cbServerHost)

    def getServerIPs(self, cbServerHost):
        """ 
        Looks up the ipv4 and ipv6 addresses of Crossbear server

        Arguments:
        cbServerHost -- Crossbear server host name (string)
        """
        # TODO find a way to get the two addresses in a single query
        # Isn't it possible to request two records?
        answers = resolver.query(cbServerHost, 'A')
        # TODO: actually, we expect there to be only one answer per
        # RR. Choose the first address of type A.
        for rdata in answers:
            if isinstance(rdata,dns.rdtypes.IN.A.A):
                self.serverIPv4 = rdata.address
                break

        answers = resolver.query(cbServerHost, 'AAAA')
        for rdata in answers:
            if isinstance(rdata,dns.rdtypes.IN.AAAA.AAAA):
                self.serverIPv6 = rdata.address
        # FIXME: deal with fail state if someone is blocking our DNS
        # E.g. find out if result is empty, and exit.
        # Also, find out what WHOIS says?

    @staticmethod
    def genAESKey(key_length):
        """
        Generates a random one session AES key

        Arguments:
        key_length -- length of key to be generated (bits)
        
        Returns:
        key -- byte array
        """
        key = RNG.get_random_bytes( key_length / 8 )
        return key

    def sendPublicIPR(self, ipv, pipReq):
        """
        Sends the Public IP Notification Request.

        Arguments:
        ipv -- IP version, 4 or 6 (integer)
        pipReq -- the Public IP Notification Request (PipReq)

        Returns:
        content of request (requests.content)
        """
        
        # Simplified - RH
        if ((ipv == 6 and self.serverIPv6 == None) 
            or (ipv == 4 and self.serverIPv4 == None)):
            # TODO: log
            print "Couldn't connect to the crossbear server using IPv%d" % ipv
            return None
        
        # TODO: do we still need the try/catch?
        # Actually send via HTTP POST
        try:
            if ipv == 6:
                ips = "[%s]" % self.serverIPv6
            else:
                ips = self.serverIPv4
            # send using the Python requests module
            data = MessageList.getBytesForMessage(pipReq)
            r = requests.post(url = "http://%s/getPublicIP.jsp" % ips,
                             data = data)
            return r.content
        except IOError, e:
            # TODO Log usefully what happend
            print "Couldn't connect to the crossbear server using IPv%d" % ipv
            print e
            return None

    def getPublicIPN(self, ipv):
        """
        Create a Public IP notification request, send it to Crossbear
        server by calling sendPublicIPR(), and obtain the reply.

        Arguments:
        ipv -- IP version, 4 or 6 (integer)

        Returns:
        Public IP notification
        """
        # generate AES key
        aeskey = PipFetcher.genAESKey(256)
        
        # encrypt the AES key
        oaep = PKCS1_OAEP.new(self.pkey)
        reKey = oaep.encrypt(aeskey)
        
        pipReq = PipReq(reKey)
        reply  = self.sendPublicIPR(ipv, pipReq)
        
        # decrypt the reply
        iv     = reply[:16]
        aes    = AES.new(aeskey, AES.MODE_CBC, iv)
        ptext  = aes.decrypt(reply[16:])

        unpadder = PKCS7()
        decMsg = unpadder.decode(ptext)


        # decrypted message `decMsg` has the form plaintext|supposed hash
        sHash  = decMsg[-32:]
        pText  = decMsg[:-32]
        hasher = SHA256.new()
        hasher.update(pText)
        aHash  = hasher.digest()
        
        if aHash != sHash:
            # TODO: should we really crash to console here?
            raise (ValueError, "Decoding failed beccause of an unexpected" +
        " message type!")
        # Check if the message is a Public IP notification for either
        # IPv4 or IPv6
        # TODO: shouldn't we check here if the value is the expected
        # IP version?
        return PipNot(sHash, pText[3:])


