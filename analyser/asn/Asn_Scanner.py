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
import sys
import os.path



import logging
import PyASN
import Queue
import threading
import psycopg2
from misc.Scanner import Scanner

class AsnScanner(Scanner):
	def __init__(self, main_config_file_loc):
		super(AsnScanner, self).__init__(main_config_file_loc)
		# pyASN actually queries the Databases
		self.asn_mapfile = self.mainConfig.get("asn", "mapfile")
		self.pyasn = PyASN.new(self.asn_mapfile)

	def start_scan(self, ips):
		sql = "INSERT INTO asn_results (ip, asn) values (%s, %s);"
		cur = self.db.cursor()
		for ip in ips:
			asn = self.pyasn.Lookup(ip)
			cur.execute(sql, (ip, asn))

if __name__ == "__main__":
	import misc.DomainHandler
	ips = misc.DomainHandler.IPSupplier("asn.config")
	asns = AsnScanner("asn.config")
	asns.start_scan(ips.get(1))
