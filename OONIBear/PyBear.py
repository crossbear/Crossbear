#!/usr/bin/python

import argparse
import os
from pyhunter import PyHunter

if os.geteuid() != 0:
    exit("    PyBear can only be run as root.")

parser = argparse.ArgumentParser(description="Python implementation of Crossbear")
parser.add_argument('cbhostname', help="Hostname of Crossbear server")
parser.add_argument('cbservercert', help="Filename of Crossbear server certificate")
parser.add_argument('tracermaxhops', help="Max number of hops per trace.", type=int)
parser.add_argument('tracersamplesperhop', help="Number of samples per hop.", type=int)
parser.add_argument('tracerperiod', help="???", type=int)
                                 

args = parser.parse_args()
hunter = PyHunter.PyHunter(args.cbhostname, args.cbservercert, args.tracermaxhops, args.tracersamplesperhop, args.tracerperiod)

hunter.getHTL()
hunter.executeHTL()
#TODO: Report printen
