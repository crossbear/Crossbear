#!/usr/bin/python
#   This file parses ip-db.com requests
#
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

# ip-db.com does NOT work with IP v6

from lxml import html
from lxml.html.clean import clean_html
import re

class IpDbParser(object):

	""" @param addr: IPv4 address as string """
	def __init__(self, addr):
		self.address = addr.strip()

	def queryIpDb(self):
		# the the reponse from ip-db.com
		tree = html.parse('http://www.ip-db.com/'+self.address)

		# Extracting the interessting values -> using the <font> tags here, this may change someday ...
		table = tree.xpath('//table/tr/td[not(@colspan)]/font[@size]')

		keys = []
		values = []
		for entry in table:
			entry = entry.text_content().strip()
			if entry.endswith(":"):
				keys.append(entry.strip(":"))
			else:
				values.append(entry)

		# unfortunately country  appears multiple times with different values. 
		# This first appearance is however the most reliable
		result = {}
		for k,v in zip(keys,values):
			if k in result:
				continue
			result[k] = v

		return result
