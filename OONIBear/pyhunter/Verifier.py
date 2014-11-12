import logging
import random
import socket
import urllib
import re
import itertools
from cbutils.LoggingMessages import HTSuccessMsg, VerifySuccessMsg, HTFailMsg, VerifyFailureMsg
from cbutils.SingleTrustHTTPS import SingleTrustHTTPS
from cbutils import MessageUtils
from cbutils.CertUtils import get_chain
from cbmessaging.CertVerifyRes import CertVerifyRes
from cbmessaging.CertVerifyReq import CertVerifyReq
from cbmessaging.MessageList import MessageList
from cbmessaging.MessageTypes import messageTypes
from cbutils.SingleTrustHTTPS import SingleTrustHTTPS

import dns
import OpenSSL

class Verifier:
    def __init__(self, url, country, cert, cbhostname, num_hosts):
        # TODO: Add two loggers, one structured for Verify and HT
        # results, another for logging arbitrary error messages.
        # so we can replace the "print" statements.
        self.logger = logging.getLogger(__name__)
        self.protector_url = url
        self.protector_country = country
        self.cert = cert
        self.cbhostname = cbhostname
        self.num_hosts = num_hosts

    def doVerify(self):
        hosts  = self.get_hosts()
        if hosts == None:
            print("getHosts failed. aborting verification.")
            return

        if self.num_hosts < len(hosts):
            hosts = random.sample(hosts,
                                  self.num_hosts)
        for host in hosts:
            ips = Verifier.resolve_ips(host)
            if not ips:
                self.logger.error(VerifyFailureMsg(host, 0, "Could not resolve hostname."))
                return
            for ip in ips:
                try:
                    print("Retrieving chain for %s (hostname %s)" % (ip, host))
                    chain = get_chain(ip, 443)
                    cvr = CertVerifyReq()
                    # TODO: Find out whether we are behind an SSL proxy
                    cvr.createFromValues(0, chain, host, ip, 443)
                    response = self.send_verify(self.cert, self.cbhostname, cvr)
                    if response != None:
                        self.logger.info(VerifySuccessMsg(host, ip, response.rating, response.judgement))
                except socket.gaierror as e:
                    print "Skipping cert verification of %s due to unsupported IP version (address: %s). Error: %s" % (host, ip, e)
                    self.logger.error(VerifyFailureMsg(host, ip, "Unsupported IP version"))
                except socket.timeout as e:
                    print "Skipping cert verification of %s (IP %s) due to timeout. Error: %s" % (host, ip, e)
                    self.logger.error(VerifyFailureMsg(host, ip, "Timeout"))
                except OpenSSL.SSL.SysCallError as e:
                    print "Skipping cert verification of %s (IP %s) due to OpenSSL syscall error. Error: %s" % (host, ip, e)
                    self.logger.error(VerifyFailureMsg(host, ip, "OpenSSL syscall error"))


    def get_hosts(self):
        conn = SingleTrustHTTPS(self.cert, self.cbhostname, 443)
        url = self.protector_url + "?" + urllib.urlencode({"country": self.protector_country})
        conn.request("GET", url)
        response = conn.getresponse()
        if response.status != 200:
            print("Error retrieving list of observation URLs from %s/%s: Error %d, %s" % (self.cbhostname, url, response.status, response.reason))
            return
        content = response.read()
        return [x.strip() for x in re.split(" |\n", content.strip())]

    @staticmethod
    def resolve_ips(host):
        answers_ipv4 = []
        try:
            answers_ipv4 = dns.resolver.query(host, "A")
        except dns.resolver.NoAnswer:
            print "Error querying A records for host %s: No answer" % (host, str(e))

        answers_ipv6 = []
        try:
            answers_ipv6 = dns.resolver.query(host, "AAAA")
        except dns.resolver.NoAnswer:
            print "Error querying AAAA records for host %s: No answer" % (host)

        result = []
        for rr in itertools.chain(answers_ipv4, answers_ipv6):
            result.append(rr.address)
            return result

    def send_verify(self, cert, cbhostname, cvr):
        conn = SingleTrustHTTPS(cert, cbhostname, 443)
        conn.request("POST", "/verifyCert.jsp",
                     MessageList.getBytesForMessage(cvr))
        response = conn.getresponse()
        if response.status != 200:
            print("Failed to verify certificate. Received HTTP error code: %d" % (response.status))
            return
        content = response.read()
        ml = MessageList(content)
        if not MessageUtils.verify(ml, cert):
            print("Error:  Returned MessageList failed to verify.")
            return None
        # Return CertVerifyRes.  TODO: Use PIP, timestamp message and
        # other stuff. This requeres some restructuring of the PyHunter code.
        ret = None
        for msg in ml.allMessages():
            if msg.getType() == messageTypes["CERT_VERIFY_RESULT"]:
                ret = msg
        if ret == None:
            print("Error: CertificateVerifyRequest response did not contain a CertificateVerifyResponse!")
        return ret


