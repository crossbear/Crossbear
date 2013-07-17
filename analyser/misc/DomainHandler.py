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
import logging
import sys, os
import socket
import Queue

from datetime import datetime
from ConfigParser import SafeConfigParser

import psycopg2
import psycopg2.extras

# IPs aus Traceroute in die Scans reinwerfen, Scan pro Hunting-Task-Result-ID. Muss mit angegeben werden!
class IPSupplier(object):

    def __init__(self, config_file):
        self.config = SafeConfigParser()
        self.config.read(config_file)
	self.crossbeardb = psycopg2.connect(
	    host = self.config.get("crossbeardb", "host"),
	    user = self.config.get("crossbeardb", "user"),
	    database = self.config.get("crossbeardb", "dbname"),
	    password = self.config.get("crossbeardb", "password"))
        
    def get_htr_ips(self, htrid):
        result = []
	cursor = self.crossbeardb.cursor(cursor_factory = psycopg2.extras.DictCursor)
	cursor.execute("SELECT trace FROM huntingtaskresults where id = %s", (htrid,))
	for row in cursor:
	    for ip in row['trace'].split("\n"):
		for ip2 in ip.split("|"):
		   result.append(ip2)
	cursor.close()
        return result

    def get_ht_ips(self, htid):
        result = []
        cursor = self.crossbeardb.cursor(cursor_factory = psycopg2.extras.DictCursor)
        cursor.execute("SELECT id FROM huntingtaskresults WHERE huntingtaskid = %s;", (htid,))
        for row in cursor:
            result.extend(self.get_htr_ips(row['id']))
        cursor.close()
        return result

    def __del__(self):
	self.crossbeardb.close()


if __name__ == "__main__":
    q = Queue.Queue()
    ips = IPSupplier("analyser.config")
    for i in ips.get(1):
	print i
