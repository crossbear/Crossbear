#!/usr/bin/python

import sys
# TODO: Rename to CamelCase
from asn.Asn_Scanner import AsnScanner
from geoip.GeoIp_Scanner import GeoIPScanner
from whois.Whois_Scanner import WhoisScanner
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
