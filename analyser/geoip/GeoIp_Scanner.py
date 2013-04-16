#!/usr/bin/python
#   This file uses all Geo location services and executes them requests
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

#from IpDbParser import IpDbParser
import MaxMind as MaxMind
import socket, sys
import threading

import logging
import sys
import PyASN, socket
import Queue


class GeoIPStats(object):
	def __init__(self, dbQueue, prefix, domain):
		self.dbQueue = dbQueue
		self.prefix = prefix
		
		self.domain = domain
		
		self.ips_in_diff_cities = []
		self.ips_in_diff_countries = []
		self.nr_diff_ip_ranges = []
		self.all_ips_same_country = 0 # handled as bool
		
	def calcStats(self, record):
		"""
			Calculates statistic values
			for each IP address to a given
			hostname
		"""
		# record['city'] is often None,
		#	 if so, don't add
		if record['city']: 
			if record['city'] not in self.ips_in_diff_cities:
				self.ips_in_diff_cities.append(record['city'])
			
		if record['country_code3'] not in self.ips_in_diff_countries:
			self.ips_in_diff_countries.append(record['country_code3'])
		
		ipRange = (record['ipStart'], record['ipEnd'])
		if ipRange not in  self.nr_diff_ip_ranges:
			self.nr_diff_ip_ranges.append(ipRange)
		
	def storeEval(self):
		"""
			Stores the gathered stats
		"""
		sql = "INSERT INTO %seval_geo " % self.prefix
		sql = sql + """(host_id, ips_in_diff_cities, 
				ips_in_diff_countries, nr_diff_ip_ranges, 
				all_ips_same_country) 
				VALUES ("""+self.prefix+"""insert_unique_domain(%s),
				%s, %s, %s, %s) """
				
		if len(self.ips_in_diff_countries) == 1:
			self.all_ips_same_country = 1
			
		sql_data = (self.domain, len(self.ips_in_diff_cities), 
			len(self.ips_in_diff_countries), len(self.nr_diff_ip_ranges), 
			self.all_ips_same_country)
		
		self.dbQueue.put( (sql, sql_data) )
		
class GeoIPStore(object):
	def __init__(self, dbQueue, prefix):
		"""
		@param dbQueue: Queue.Queue for passing things to store to StorageThread
		@param prefix: prefix of schema
		"""
		self.dbQueue = dbQueue
		self.prefix = prefix
		
	def storeDomainInfo(self, domain):
		sql = "INSERT INTO %sdomains " % self.prefix
		sql += "(fqdn, scan_time) VALUES (%s, (SELECT TIMESTAMP 'now'))"
		
		self.dbQueue.put( (sql, (domain,)) )
		
	def storeGeoInfo(self, domain, record):
		"""
		@param domain: domain name from url list
		@param record: dictionary with all available information to given ip address
		"""
		sql = "INSERT INTO %sgeoInfo " % self.prefix
		sql = sql + """(host_id, ip, city, region_name, region, time_zone,
				longitude, latitude, metro_code, country_code, country_code3,
				country_name, postal_code, dma_code, ipStart, ipEnd) 
				VALUES ("""+self.prefix+"""insert_unique_domain(%s),
				%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) """
				
		sql_data = ( domain, record['address'], record['city'], 
			record['region_name'], record['region'], record['time_zone'], 
			record['longitude'], record['latitude'], record['metro_code'], 
			record['country_code'], record['country_code3'], record['country_name'], 
			record['postal_code'], record['dma_code'], 
			record['ipStart'], record['ipEnd'] )
		
		self.dbQueue.put( (sql, sql_data) )
	
class GeoIPQueryThread(threading.Thread):
	def __init__(self, dbQueue, taskQueue, prefix, cityDbPath, cityDbDatPath, cityDbDatPath_backup, maxmind_url):
		"""
			@param dbQueue: Queue.Queue for passing things to store to StorageThread
			@param prefix: prefix of schema
			@param maxMind: MaxMind object with connected city DB
			...
		"""
		self.dbQueue = dbQueue
		self.taskQueue = taskQueue
		self.prefix = prefix
		self.cityDbPath = cityDbPath
		self.cityDbDatPath = cityDbDatPath
		self.cityDbDatPath_backup = cityDbDatPath_backup
		self.maxmind_url = maxmind_url
		
		self.maxMind = MaxMind.MaxMind( cityDbDatPath )
		
		threading.Thread.__init__(self)
			
	def run(self):
		# make sure you got the most recent City DB file
		maxUpdater = MaxMind.MaxMindUpdater(self.prefix, self.cityDbPath, 
			self.cityDbDatPath, self.cityDbDatPath_backup , self.maxmind_url)
		maxUpdater.update()
		
		# New domain, new geo ip stats
		geoIpStore = GeoIPStore(self.dbQueue, self.prefix)
		
		while True:
			# Get domain and IPs
			domain, ip_list_for_domain = self.taskQueue.get()
			try:
				# Stats object
				evalGeoIp = GeoIPStats(self.dbQueue, self.prefix, domain)
				
				# Store fqdn
				geoIpStore.storeDomainInfo( domain )
				
				# Perform queries to MaxMind DB
				for ip in ip_list_for_domain:
					record = self.maxMind.queryDB(ip)
					if not record:
						continue
					geoIpStore.storeGeoInfo( domain, record )
					evalGeoIp.calcStats( record )
				
				# Finalize analysis on host, write to DB
				evalGeoIp.storeEval()
				del(evalGeoIp)
			finally:
				self.taskQueue.task_done()
