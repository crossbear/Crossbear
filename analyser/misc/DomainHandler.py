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
import threading
import re
from netaddr import all_matching_cidrs

from datetime import datetime
from ConfigParser import SafeConfigParser
from DB import DbPool
from StorageThread import StorageThread


# IPs aus Traceroute in die Scans reinwerfen
class DomainHandler(threading.Thread):
	def __init__(self, main_config_file_loc):
		"""
			Superclass for managing the domain 
			handling 
		"""
		self.mainConfig = SafeConfigParser()
		self.mainConfig.read(main_config_file_loc)
		
		# prefix/schema to use in DB:
		self.prefix = ""
		if self.mainConfig.has_option("database", "prefix"):
			self.prefix = self.mainConfig.get("database", "prefix")
			
		self.storageThreads = self.mainConfig.getint("processing", "storage_threads")
		#self.threadCount = mainConfig.getint("processing", "scan_threads")
			
		dbname = self.mainConfig.get("database", "db_domain_handler")
		self.db = DbPool(self.mainConfig, dbname)
	
		self.dbQueue = Queue.Queue(30)
	
		self.t = StorageThread(self.db, self.dbQueue)
		self.t.setDaemon(True)
		self.t.start()
		

class InitialDomainAdd(DomainHandler):
	def __init__(self, main_config_file_loc):
		super(InitialDomainAdd, self).__init__(main_config_file_loc)
		
		# Blacklisted IPs and domains
		self.bl_IPs = []
		self.bl_domains = []
		self.current_domain_file = ""
		
		
	def _getIpListForDomain(self, domain):
		try:
			addr_details = socket.gethostbyname_ex(domain)
			return addr_details[-1]
		
		except socket.gaierror:
			# [Errno -2] Name or service not known
			return None
			
	
	def _insertInitalDomainInformation(self, domain, resolvable, forbidden):		
		# Prohibit double insertions
		sql = "INSERT INTO %sdomains " % self.prefix
		sql += "(domain, resolvable, forbidden, dns_last_checked, source_id) "
		sql += "(SELECT %s as domain, %s as resolvable, %s as forbidden, "
		sql += "%s as dns_last_checked, "+self.prefix+"insert_unique_source(%s) as source_id "
		sql += "WHERE NOT EXISTS (SELECT 1 FROM "
		sql += "%sdomains WHERE domain='%s'))" % (self.prefix, domain)
		
		dns_last_checked = datetime.now().isoformat()
		file_path, source = os.path.split(self.current_domain_file)
		
		sql_data = (domain, resolvable, forbidden, dns_last_checked, source)
		self.dbQueue.put( (sql, sql_data) )
		
	def _insertInitalScanInformation(self, domain, ip):
		# After successfully scanning the host
		sql = "INSERT INTO %sscans " % self.prefix
		sql += """(host_id, ip, asn, geoip, dns_scraper, whois, nmap)
				VALUES ("""+self.prefix+"""insert_unique_domain(%s),
				%s, %s, %s, %s, %s, %s)"""
		
		# marking scans with 0 meaning they are not scanned yet
		sql_data = (domain, ip, 0, 0, 0, 0, 0)
		
		self.dbQueue.put( (sql, sql_data) )
	
	def _is_ip_forbidden(self, domain, ip_list_for_domain):
		for ip in ip_list_for_domain:
			if all_matching_cidrs(ip, self.bl_IPs):
				self._insertInitalDomainInformation(domain, resolvable=0, forbidden=1)
				# continue, domain needs to be blocked only once.
				# Please bear in mind, even if the IP blongs to another domain, 
				#  the domain will be flagged forbidden as well
				return True
		return False
	
	def processDomainFileToDB(self, dF_loc):
		"""
			Reads the content of the Domain file
			and stores the domain, if unique in the DB
		"""
		try:
			dF = open(dF_loc, 'r')
			self.current_domain_file = dF_loc
			
			for domain in dF:
				domain = domain.strip()
				
				# Is domain blocked itself?
				if domain in self.bl_domains:
					self._insertInitalDomainInformation(domain, resolvable=0, forbidden=1)
					continue
				
				ip_list_for_domain = self._getIpListForDomain(domain)
				
				# Did we get any IPs for the given domain?
				if not ip_list_for_domain:
					self._insertInitalDomainInformation(domain, resolvable=0, forbidden=0)
					continue
				
				# There are IPs, shall they be excluded from the scans?
				if self._is_ip_forbidden(domain, ip_list_for_domain):
					continue
				
				# Standard case, everything is fine, domain is resolvable and allowed to be scanned
				self._insertInitalDomainInformation(domain, resolvable=1, forbidden=0)
				for ip in ip_list_for_domain:
					self._insertInitalScanInformation(domain, ip)
			
			dF.close()
		except IOError:
			# [Errno 2] No such file or directory
			return
			
		
	def processBlacklistedDomains(self, blF_loc):
		"""
			@param blF_loc: Location of the blacklisted domain file
			
			Reads the content of the Domain file
			and keeps it in a dict
		"""
		try:
			blF = open(blF_loc, 'r')
			for line in blF:
				line = line.strip()
				
				# For comments
				if line.startswith('#'):
					continue
				
				# Lets see if the line is CIDR coded
				if re.search('^([0-9]{1,3}\.){3}[0-9]{1,3}($|/(16|24))$', line):
					self.bl_IPs.append(line)
				else:
					self.bl_domains.append(line)
			blF.close()
			
		except IOError:
			# [Errno 2] No such file or directory
			return
	
class DomainSupplier(DomainHandler):
	"""
		Offers a series of domains an their associated ip
		addresses in form dict.
	"""
	def __init__(self, main_config_file_loc, taskQueue, scanner):
		"""
			@param main_config_file_loc: self explanatory
			@param scanner: name of scanner and is here used as the column
					in the table (_insertInitalScanInformation)
		"""
		super(DomainSupplier, self).__init__(main_config_file_loc)
		self.taskQueue = taskQueue
		self.scanner = scanner
		self.rows = self._fetchDomainsFromDB()
		
		# Keep this the last step.
		threading.Thread.__init__(self)
	
	def _updatedScannedIPs(self, d_id, ip):
		"""
			Marks the ip address as scaned for a given scanner
			@param d_id: id(primary key) of domain in database
			@param ip: ip address of scanned host
			@param scanner: column name, which is also name of the scanner
		"""
		sql = "UPDATE %sscans SET %s=1 " % (self.prefix, self.scanner)
		sql += "WHERE host_id=%s AND ip=%s"
		
		sql_data = (d_id, ip)
		self.dbQueue.put( (sql, sql_data) )
		
	def _fetchDomainsFromDB(self):
		"""
			Gets Domain entries from DB
			
			Remark: this step has to be done before the Thread is
			started. Otherwise it won't work
		"""
		sql = "SELECT d.id, d.domain, s.ip "
		sql += "FROM %sdomains d JOIN %sscans s " % (self.prefix, self.prefix)
		sql += "ON d.id=s.host_id "
		sql += "WHERE %s=0 AND d.resolvable=1 AND d.forbidden=0 " % self.scanner
		sql += "ORDER BY d.domain"
		
		try:
			dbCursor = self.db.cursor()
			dbCursor.execute(sql)
			rows = dbCursor.fetchall()
		finally:
			self.db.commit()
		
		return rows
	
	def _domainGenerator(self):
		try:
			for row in self.rows:
				yield(row)
		except StopIteration:
			pass
			
	def run(self):
		# In the next step we have to efficiently
		#  aggregate a domain with it's IP addresses
		prev_domain = ""
		ips_of_prev_domain = []
		
		domainGenerator = self._domainGenerator()
		
		for row in domainGenerator:
			d_id, domain, ip = row
			
			# There are multiple IPs for a given domain
			# store them in the list
			if domain == prev_domain:
				ips_of_prev_domain.append(ip)
			else:
				# There are no more IPs belonging to the prev_domain
				
				# store date if not None
				if prev_domain and ips_of_prev_domain:
					self.taskQueue.put(( prev_domain, ips_of_prev_domain ))
					
				# set current domain and ip as prev* 
				prev_domain = domain
				ips_of_prev_domain = [ip]
			
			# update scan status
			self._updatedScannedIPs(d_id, ip)
