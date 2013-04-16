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

from yawhois import yawhois

class WhoisStats(object):
	def __init__(self):
		"""
			Creates statistic from the Whois queries
		"""		
		# Certain, mostly smaller hosts use Nservers
		# form for example google
		self.domain_uses_own_nserver = 0 # bool
		self.nr_nservers = 0

		self.dates_unavailable = 0		
		self.all_dates_available = 0 # bool
		self.no_dates = 0 # bool
	
		
	def calcStats(self, list_nserver_sql_data):
		"""
			Calculates statistic values
			for each IP address to a given
			hostname
		"""
		self.nr_nservers = len(list_nserver_sql_data)

		if self.dates_unavailable == 0:
			self.all_dates_available = 1

		if self.dates_unavailable == 3:
			self.no_dates = 1
			

class WhoisStore(object):
	def __init__(self, dbQueue, prefix):
		"""
			Writes the findings from the Whois,
			and their stats to the DB
		"""
		self.dbQueue = dbQueue
		self.prefix = prefix
		
	def storeDates(self, sql_data):
		sql = "INSERT INTO %swhois " % self.prefix
		sql = sql + """(fqdn, update_date, create_date, expiration_date, scan_time)
				VALUES (%s, """+self.prefix+"""to_null_timestamp(%s, 'YYYY-MM-DD'), 
				 """+self.prefix+"""to_null_timestamp(%s, 'YYYY-MM-DD'), 
				 """+self.prefix+"""to_null_timestamp(%s, 'YYYY-MM-DD'),
				 (SELECT TIMESTAMP 'now'))"""
		
		try:
			self.dbQueue.put((sql, sql_data))
		except:
			logging.error("Could not store whois information")
			
		
	def storeNS(self, list_nserver_sql_data):
		if not list_nserver_sql_data:
			# No Nserver entry for given host
			return None
		
		sql = "INSERT INTO %swhoisNS " % self.prefix
		sql = sql + """(host_id, nserver)
				VALUES ("""+self.prefix+"""insert_unique_domain(%s), %s)
				"""
		try:
			for sql_data in list_nserver_sql_data:
				self.dbQueue.put((sql, sql_data))
		except:
			logging.error("Could not store Nserver information")

	def storeEval(self, domain, whoisStats):
		sql = "INSERT INTO %seval_whois " % self.prefix
		sql = sql + """(host_id, domain_uses_own_nserver, nr_nservers, dates_unavailable, 
				all_dates_available, no_dates)
				VALUES ("""+self.prefix+"""insert_unique_domain(%s), %s, %s, %s, %s, %s)
				"""
		sql_data = (domain, whoisStats.domain_uses_own_nserver, whoisStats.nr_nservers,
					whoisStats.dates_unavailable, whoisStats.all_dates_available,
					whoisStats.no_dates)
		try:
			self.dbQueue.put((sql, sql_data))
		except:
			logging.error("Could not store eval information for domain: %s", domain)



class WhoisQueryThread(threading.Thread):

	def __init__(self, taskQueue, dbQueue, prefix, addrPoolObject):
		"""Create scanning thread.
		
		@param taskQueue: Queue.Queue containing domains to scan as strings
		@param dbQueue: Queue.Queue for passing things to store to StorageThread
		@param opts: instance of DnsConfigOptions
		@param prefix: prefix of schema
		@param addrPoolObject: The BindAddr Object to retrieve different IPs to make the 
				request with
		"""
		self.taskQueue = taskQueue
		self.dbQueue = dbQueue
		self.prefix = prefix
		self.addrPoolObject = addrPoolObject
		
		threading.Thread.__init__(self)
		
		
	def _getDates(self, ya, domain, whoisStats):
		""" 
			Extracts dates (e.g. expiration_date) from 
			query
			For some domains not all of the desired
			dates are available.
		"""
		ud = ""
		cd = ""
		ed = ""
		try:
			ud = ya.update_date.isoformat()
		except:
			whoisStats.dates_unavailable += 1
		
		try:
			cd = ya.create_date.isoformat()
		except:
			whoisStats.dates_unavailable += 1

		try:
			ed = ya.expiration_date.isoformat()
		except:
			whoisStats.dates_unavailable += 1
		
		# This form is expected when passing on to DB for storage
		return (domain, ud, cd, ed)
	
	def _getNservers(self, domain, ya, whoisStats):
		""" 
			Extracts Nserver information from 
			query. Could be None though
			Hint: Some of the name server entries 
				are in CAPITAL LETTERS
				
				Also some entries are in the format
					]                ns01.yahoo.co

			Checks also if domain uses own Nserver
		"""
		domain_name = domain.split('.')[0].lower()

		list_nserver_sql_data = []
		try:
			for ns in ya.soa:
				if domain_name in ns.lower():
					whoisStats.domain_uses_own_nserver = 1
				list_nserver_sql_data.append( (domain, ns.lower()) )
		except:
			return []
			
		return list_nserver_sql_data
	
	def run(self):
		
		whoisStore = WhoisStore(self.dbQueue, self.prefix)
		
		while True:
			try:
				# Here ip_list_for_domain is not being used. 
				# 	We are only interessted in the domain
				domain, ip_list_for_domain = self.taskQueue.get()
				
				if not domain.startswith('www.'):
					# Get the IP under which the request will be made
					
					# TODO re-enable if using a machine with multiple
					# IP addresses
					#bind_addr = self.addrPoolObject.get_bind_addr(domain)
					bind_addr = '131.159.15.216'
					ya = yawhois.yawhois(domain, bind_addr)
					
					whoisStats = WhoisStats()
					
					dates_sql_data = self._getDates(ya, domain, whoisStats)
					list_nserver_sql_data = self._getNservers(domain, ya, whoisStats)
					
					whoisStore.storeDates(dates_sql_data)
					whoisStore.storeNS(list_nserver_sql_data)

					# Generate Stats
					whoisStats.calcStats(list_nserver_sql_data)
					whoisStore.storeEval(domain, whoisStats)
					del(whoisStats)
					
					# TODO remove sleep when having multiple IPs
					# at your disposal
					time.sleep(1)
			except:
				logging.exception("Fetching-Error for %s", domain)
			finally:	
				self.taskQueue.task_done()