#!/usr/bin/python

import argparse
import ConfigParser
import os
import itertools
import socket
import cbutils.MessageUtils
import OpenSSL
import logging
from pyhunter import PyHunter
from pyhunter import Verifier
from cbutils.CertUtils import get_chain
from cbmessaging import CertVerifyReq
from cbmessaging.MessageList import MessageList
from cbmessaging.MessageTypes import messageTypes
from cbmessaging.CertVerifyRes import CertVerifyRes
from cbmessaging.CertVerifyReq import CertVerifyReq
from cbutils.SingleTrustHTTPS import SingleTrustHTTPS
from dns import resolver

if os.geteuid() != 0:
    exit("    PyBear can only be run as root.")

parser = argparse.ArgumentParser(description="Python implementation of Crossbear")
parser.add_argument('--config','-c', help="Config filename", default="./cb.conf", dest="configfile")
args = parser.parse_args()

cp = ConfigParser.RawConfigParser()
cp.read(args.configfile)

logging.basicConfig(filename=cp.get("General", "logfile"), format="%(asctime)s | %(message)s", level=logging.DEBUG)


certificate = cp.get("Server", "cb_cert")
cbhost = cp.get("Server", "cb_host")

verifier = Verifier.Verifier("getObservationUrls.jsp",
                             cp.get("Protector", "country"),
                             certificate,
                             cbhost,
                             cp.get("Protector", "num_hosts"))
verifier.doVerify()

hunter = PyHunter.PyHunter(cp.get("Server", "cb_host"),
                           cp.get("Server", "cb_cert"),
                           cp.getint("Tracer", "max_hops"),
                           cp.getint("Tracer", "samples_per_hop"),
                           cp.getint("Tracer", "period"))

hunter.getHTL()
hunter.executeHTL()
#TODO: Report printen
