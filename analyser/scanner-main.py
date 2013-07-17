#!/usr/bin/python

import sys
# TODO: Rename to CamelCase
from asn.AsnScanner import AsnScanner
from geoip.GeoIPScanner import GeoIPScanner
from whois.WhoisScanner import WhoisScanner
from misc.DomainHandler import IPSupplier


configfile = sys.argv[1]
htid = sys.argv[2]


d = IPSupplier(configfile)

asn = AsnScanner(configfile)
geoip = GeoIPScanner(configfile)
whois = WhoisScanner(configfile)
ips = d.get_ht_ips(htid)

asn.start_scan(ips)
whois.start_scan(ips)
geoip.start_scan(ips)
