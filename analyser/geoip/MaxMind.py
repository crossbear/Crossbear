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

class MaxMindUpdater(object):
	def __init__(self, prefix, cityDbPath, cityDbDatPath, cityDbDatPath_backup , maxmind_url):
		self.locGeoLiteCityDb = cityDbPath # is the *.gz packed file
		self.locGeoLiteCityDbDat = cityDbDatPath
		self.cityDbDatPath_backup = cityDbDatPath_backup 
		self.maxmind_url = maxmind_url
		self.prefix = prefix
	
	def _getBackupFileName(self):
		"""
			Use prefix and former filename to get filename for 
			backing up the old GeoLiteCity DB
		"""
		if self.prefix.endswith('.'):
			self.prefix = self.prefix[:-1]
		db_dir, db_filename = os.path.split(self.locGeoLiteCityDbDat)
		filename_parts = db_filename.split('.')
		new_db_filename = filename_parts[0] + "_" + self.prefix + "." + filename_parts[1]
		
		return os.path.join(self.cityDbDatPath_backup, new_db_filename)
	
	def _checkForDBUpdate(self):
		# IF file already exists, check if updates are available
		if os.path.isfile(self.locGeoLiteCityDb):
			try:
				remoteFile = urllib2.urlopen(self.maxmind_url)
				rFileSize = long(remoteFile.headers["Content-Length"])
				lFileSize = long(os.path.getsize(self.locGeoLiteCityDb))
				remoteFile.close()
			
				if rFileSize == lFileSize:
					print("MaxMind DB is up to date ... ")
					return False
				else:
					print('Saving copy of the old GeoLiteCity DB ...')
					shutil.copy(self.locGeoLiteCityDbDat, self._getBackupFileName())
					os.remove(self.locGeoLiteCityDb)
					os.remove(self.locGeoLiteCityDbDat)
				
				return True
			
			except urllib2.HTTPError, e:
				print "HTTP Error: ", e.code
				print "Assuming DB okay"
				return False
			except urllib2.URLError, e:
				print "URL Error: ", e.reason
				print "Assuming DB okay"
				return False
		
		
	def update(self):
		if self._checkForDBUpdate():
			print('Need to fetch copy of GeoLiteCity DB, please wait a sec ...')
		
			# Download file
			try:
				downloadFile = urllib2.urlopen(self.maxmind_url)
				# Open our local file for writing
				with open(self.locGeoLiteCityDb, "wb") as local_file:
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
			compressed = gzip.open(self.locGeoLiteCityDb, 'rb')
			extracted = open(self.locGeoLiteCityDbDat, 'w')
			extracted.write(compressed.read())
			extracted.close()
			compressed.close()
			print('Updated version of MaxMind City DB.')
		else:
			print ('No need to update MaxMind City DB.')
			

class MaxMind(object):
	def __init__(self, cityDbDatPath):
		self.locGeoLiteCityDbDat = cityDbDatPath
		self.gi = GeoIP.open(self.locGeoLiteCityDbDat,GeoIP.GEOIP_STANDARD)
	
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
