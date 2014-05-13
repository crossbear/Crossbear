#!/usr/bin/python

import argparse
import ConfigParser
import os
from pyhunter import PyHunter

if os.geteuid() != 0:
    exit("    PyBear can only be run as root.")


parser = argparse.ArgumentParser(description="Python implementation of Crossbear")
parser.add_argument('--config','-c', help="Config filename", default="./cb.conf", dest="configfile")
args = parser.parse_args()

cp = ConfigParser.RawConfigParser()

cp.read(args.configfile)

# TODO: Get list of URLs and issue verify requests for them.

hunter = PyHunter.PyHunter(cp.get("Server", "cb_host"),
                           cp.get("Server", "cb_cert"),
                           cp.getint("Tracer", "max_hops"),
                           cp.getint("Tracer", "samples_per_hop"),
                           cp.getint("Tracer", "period"))

hunter.getHTL()
hunter.executeHTL()
#TODO: Report printen
