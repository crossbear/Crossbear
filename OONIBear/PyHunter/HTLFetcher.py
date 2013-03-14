"""
HuntingTask List fetcher for crossbear implemented in python.
The hash of the server certificate needs to be a sha256 hash
"""

__author__ = "Vedat Levi Alev"

from cbmessaging.Message import Message
from cbmessaging.HuntingTask import HuntingTask
from cbmessaging.SignatureMessage import SignatureMessage
from cbutils.SingleTrustHTTPS   import SingleTrustHTTPS
from Crypto.Hash import SHA256
from M2Crypto import BIO, RSA, EVP
from cbmessaging.PipNot  import PipNot
from cbmessaging.CurServTime import CurServTime

class HTLFetcher(object):

    def __init__(self, servHost, servPort, servCert):
        self.servHost     = servHost
        self.servPort     = servPort
        self.servCert     = servCert



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
        ml = MessageList(resp)
        return ml

    def verify(self, messagelist):
        messageindex = 0
        for index in messagelist.length():
            if typeof(messagelist.getMessage(index)) is cbmessaging.SignatureMessage:
                messageindex = index
                break
        sigmessage = l.getMessage(messageindex)
        l.removeMessage(messageindex)
        toverify = l.getBytes()
        # TODO: Add correct key path
        key = RSA.load_pub_key("server-public-key.pem")
        pubkey = EVP.PKey()
        pubkey.assign_rsa(key)
        pubkey.reset_context(md="sha256")
        pubkey.verify_init()
        pubkey.verify_update(toverify)
        return (pubkey.verify_final(sigmessage.signature) == 1)
