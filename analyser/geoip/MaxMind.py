#!/usr/bin/python
#   This file queries the MaxMind city lite binary file
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

import GeoIP
import os, sys
import urllib2
import gzip
import shutil
from ConfigParser import SafeConfigParser

class MaxMindUpdater(object):
	def __init__(self, config):
		self.configfile = config
		self.conf = SafeConfigParser()
		self.conf.read(config)
		self.dbpath = self.conf.get("geoloc", "dbpath")
		self.db_backup = self.conf.get("geoloc", "db_backup")
		self.maxmind_url = self.conf.get("geoloc","dburl")
		self.size = int(self.conf.get("geoloc", "dbsize"))
	
	def _checkForDBUpdate(self):
		# IF file already exists, check if updates are available
		if os.path.isfile(self.dbpath):
			try:
				remoteFile = urllib2.urlopen(self.maxmind_url)
				rFileSize = long(remoteFile.headers["Content-Length"])
				remoteFile.close()
			
				if rFileSize == self.size:
					print("MaxMind DB is up to date ... ")
					return False
				else:
					print('Saving copy of the old GeoLiteCity DB ...')
					shutil.copy(self.dbpath, self.db_backup)
					os.remove(self.dbpath)
				
				return True
			
			except urllib2.HTTPError, e:
				print "HTTP Error: ", e.code
				print "Assuming DB okay"
				return False
			except urllib2.URLError, e:
				print "URL Error: ", e.reason
				print "Assuming DB okay"
				return False
		return True
		
		
	def update(self):
		if self._checkForDBUpdate():
			print('Need to fetch copy of GeoLiteCity DB, please wait a sec ...')
		
			# Download file
			try:
				downloadFile = urllib2.urlopen(self.maxmind_url)
				size = downloadFile.headers['Content-Length']
				self.conf.set("geoloc", "dbsize", size)
				with open(self.configfile, 'w') as f:
					self.conf.write(f)
				# Open our local file for writing
				with open(self.dbpath +".gz", "wb") as local_file:
					local_file.write(downloadFile.read())
				downloadFile.close()
			except urllib2.HTTPError, e:
				print "HTTP Error: ", e.code
				print "Assuming DB okay"
				return None
			except urllib2.URLError, e:
				print "URL Error: ", e.reason
				print "Assuming DB okay"
				return None
			
			print('Done downloading new version of GeoLiteCity DB.')
				# Decompress it
			compressed = gzip.open(self.dbpath + ".gz", 'rb')
			extracted = open(self.dbpath, 'w')
			extracted.write(compressed.read())
			extracted.close()
			compressed.close()
			os.remove(self.dbpath + ".gz")
			print('Updated version of MaxMind City DB.')
		else:
			print ('No need to update MaxMind City DB.')
			

class MaxMind(object):
	def __init__(self, dbpath):
		self.dbpath = dbpath
		self.gi = GeoIP.open(self.dbpath,GeoIP.GEOIP_STANDARD)
	
	def queryDB(self, ip):
		record = self.gi.record_by_addr(ip)
		
		# of there is no entry to a given ip
		if not record:
			return None
		
		# Apparently there is malformed data in the DB
		for key, value in record.items():
			try:
				value = str(value)
				record[key] = value.decode("utf-8")
			except UnicodeDecodeError:
				record[key] = ""
		
		# add ip to record
		record['address'] = ip
		
		# start and end ips to record
		ipRange = self.gi.range_by_ip(ip)
		record['ipStart'] = str(ipRange[0])
		record['ipEnd'] = str(ipRange[1])
		
		return record

if __name__ == "__main__":
	mmu = MaxMindUpdater("geoip.config")
	mmu.update()
