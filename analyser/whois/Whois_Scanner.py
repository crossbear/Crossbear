#!/usr/bin/python#
#   Copyright (C) 2012 Robert Kulzer
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, version 3 of the License.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
import Queue
import threading
import logging
import sys, time

from misc.Scanner import Scanner
from Whois_Client import NICClient

class WhoisScanner(Scanner):
        def __init__(self, config_file):
                super(WhoisScanner, self).__init__(config_file)
                
	def start_scan(self,ips):
                sql = "INSERT INTO whois_results (ip,whois_data) values (%s,%s);"
                cur = self.db.cursor()
                scanner = NICClient()
                for ip in ips:
                        if not self.cached(ip):
                                data = scanner.whois_lookup(None, ip, NICClient.WHOIS_RECURSE)
                                cur.execute(sql, (ip, data))
                cur.close()

if __name__ == "__main__":
        import misc.DomainHandler
        ips = misc.DomainHandler.IPSupplier("whois.config")
        whoiss = WhoisScanner("whois.config")
        whoiss.start_scan(ips.get(1))
