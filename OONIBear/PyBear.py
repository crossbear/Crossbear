#!/usr/bin/python

import argparse
import ConfigParser
import os
import itertools
import socket
from pyhunter import PyHunter
from cbutils.CertUtils import get_chain
from cbmessaging import CertVerifyReq
from cbmessaging.MessageList import MessageList
from cbmessaging.CertVerifyRes import CertVerifyRes
from cbmessaging.CertVerifyReq import CertVerifyReq
from cbutils.SingleTrustHTTPS import SingleTrustHTTPS
from dns import resolver

if os.geteuid() != 0:
    exit("    PyBear can only be run as root.")

def resolve_ips(host):
    answers_ipv4 = []
    try:
        answers_ipv4 = resolver.query(host, "A")
    except:
        print "Error querying A records for host %s" % (host,) 

    answers_ipv6 = []
    try:
        answers_ipv6 = resolver.query(host, "AAAA")
    except:
        print "Error querying AAAA records for host %s" % (host,)

    result = []
    for rr in itertools.chain(answers_ipv4, answers_ipv6):
        result.append(rr.address)
    return result

def send_verify(cert, cbhostname, cvr):
    conn = SingleTrustHTTPS(cert, cbhostname, 443)
    conn.request("POST", "/verifyCert.jsp",
                 MessageList.getBytesForMessage(cvr))
    response = conn.getresponse()
    if response.status != 200:
        print("Error submitting CertificateVerifyRequest: Error %d, %s" % (response.status, response.reason))
    content = response.read()
    ml = MessageList(content)
    # Return CertVerifyRes.
    # TODO: Use PIP, timestamp message and other stuff. This requeres some restructuring.
    for msg in ml.allMessages():
        if isinstance(msg, CertVerifyRes):
            return msg
    print("Error: CertificateVerifyRequest response did not contain a CertificateVerifyResponse!")
    return None

parser = argparse.ArgumentParser(description="Python implementation of Crossbear")
parser.add_argument('--config','-c', help="Config filename", default="./cb.conf", dest="configfile")
args = parser.parse_args()

cp = ConfigParser.RawConfigParser()

cp.read(args.configfile)

hosts = cp.get("Protector", "hosts").split(" ")
for host in hosts:
    ips = resolve_ips(host)
    for ip in ips:
        try:
            print("Retrieving chain for %s (hostname %s)" % (ip, host))
            chain = get_chain(ip, 443)
            cvr = CertVerifyReq()
            # TODO: Find out whether we are behind an SSL proxy
            print("Sending cert verify request for IP %s, host %s" % (ip, host))
            cvr.createFromValues(0, chain, host, ip, 443)
            response = send_verify(cp.get("Server", "cb_cert"), cp.get("Server", "cb_host"), cvr)
            print("Verify response from server for IP %s, host %s: %d" % (ip, host, response.rating))
        except socket.gaierror as e:
            print "Skipping cert verification of %s for unsupported IP version (address: %s)" % (host, ip)
        

hunter = PyHunter.PyHunter(cp.get("Server", "cb_host"),
                           cp.get("Server", "cb_cert"),
                           cp.getint("Tracer", "max_hops"),
                           cp.getint("Tracer", "samples_per_hop"),
                           cp.getint("Tracer", "period"))

hunter.getHTL()
hunter.executeHTL()
#TODO: Report printen
