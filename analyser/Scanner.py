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
import sys
import os
import Queue
import time
import subprocess

from ConfigParser import SafeConfigParser

# Non-Standard-Python IMPORTS

import misc.StorageThread as StorageThread
import misc.DB as DB

import asn.Asn_Scanner as Asn_Scanner
import geoip.GeoIp_Scanner as GeoIp_Scanner
import whois.Whois_Scanner as Whois_Scanner
		
class Scanners(object):
	def __init__(self, main_config_file_loc):
		"""
			@param main_config_file_loc: location of the global.config
		"""
		self.mainConfig = SafeConfigParser()
		self.mainConfig.read(main_config_file_loc)
		
		# prefix/schema to use in DB:
		self.prefix = ""
		if self.mainConfig.has_option("database", "prefix"):
			self.prefix = self.mainConfig.get("database", "prefix")
		
		self.storageThreads = self.mainConfig.getint("processing", "storage_threads")
		self.threadCount = self.mainConfig.getint("processing", "scan_threads")
		
		self.dbQueue = Queue.Queue(10)
		# Queue storing tuples in the form: (domainname, [ip1, ip2, ip3, ...])
		self.taskQueue = Queue.Queue(100)
		
	def _setUpLogFile(self, log_file_name):
		logfile_path = self.mainConfig.get("log", "logfile_path")
		logfile = os.path.join(logfile_path, log_file_name)
		
		loglevel = ""
		try:
			loglevel = getattr(logging, self.mainConfig.get("log", "loglevel").upper())
		except AttributeError:
			raise ValueError("No such loglevel")
		
		if logfile == "-":
			logging.basicConfig(stream=sys.stderr, level=loglevel,
				format="%(asctime)s %(levelname)s %(message)s [%(pathname)s:%(lineno)d]")
		else:
			logging.basicConfig(filename=logfile, level=loglevel,
				format="%(asctime)s %(levelname)s %(message)s [%(pathname)s:%(lineno)d]")

		logging.info("Starting scan of domains.")
		
	def startScanner(self, scannerName):
		# One instance of DomainSupplier
		t = DomainHandler.DomainSupplier(main_config_file_loc, self.taskQueue, scannerName)
		t.setDaemon(True)
		t.start()
		
		#for t in range(self.storageThreads):
		t = StorageThread.StorageThread(self.db, self.dbQueue)
		t.setDaemon(True)
		t.start()
	
	def waitingForQueuesToJoin(self):
		logging.info("Finished scanning threads to finish.")
		self.taskQueue.join()
		logging.info("Waiting for storage threads to finish.")
		self.dbQueue.join()

# %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
# %%%%%%%%%		ASN
# %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
class AsnScanner(Scanners):
	def __init__(self, main_config_file_loc):
		super(AsnScanner, self).__init__(main_config_file_loc)
		
		# pyASN actually queries the Databases
		self.ipasndat_file_loc = self.mainConfig.get("asn", "curr_ipasndat")
		self.ipasndat_dir = self.mainConfig.get("asn", "curr_ipasndat_dir")
		self.ipasndat_backup_file_name = self.mainConfig.get("asn", "ipasndat_backup_file_name")
		
		dbname = self.mainConfig.get("database", "db_asn")
		#  max_connections=storageThreads
		self.db = DB.DbPool(self.mainConfig, dbname)
		
		# Set up logging
		self.log_file_name = self.mainConfig.get("log", "logfile_asn")
	
	#def update_ASN_DB(self):
		# TODO baue update shell script ein!
		
	
	def start_ASN_Scan(self):
		
		super(AsnScanner, self)._setUpLogFile(self.log_file_name)
		super(AsnScanner, self).startScanner('asn')
		# use just one query thread
		t = Asn_Scanner.AsnQueryThread(self.taskQueue, self.dbQueue, self.prefix, self.ipasndat_file_loc)
		t.setDaemon(True)
		t.start()
		
		super(AsnScanner, self).waitingForQueuesToJoin()
		
# %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
# %%%%%%%%%		GEOIP
# %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
class GeoIPScanner(Scanners):
	def __init__(self, main_config_file_loc):
		super(GeoIPScanner, self).__init__(main_config_file_loc)
		
		# Fetch information regarding MaxMind DB from glaobl config file
		self.cityDbPath = self.mainConfig.get("geoloc", "cityDbPath")
		self.cityDbDatPath = self.mainConfig.get("geoloc", "cityDbDatPath")
		self.cityDbDatPath_backup = self.mainConfig.get("geoloc", "cityDbDatPath_backup")
		self.maxmind_url = self.mainConfig.get("geoloc", "maxmindURL")
		
		dbname = self.mainConfig.get("database", "db_geoip")
		#  max_connections=storageThreads
		self.db = DB.DbPool(self.mainConfig, dbname)
		
		# Set up logging
		self.log_file_name = self.mainConfig.get("log", "logfile_geoip")		
	
	def start_GeoIP_Scan(self):
		super(GeoIPScanner, self)._setUpLogFile(self.log_file_name)
		super(GeoIPScanner, self).startScanner('geoip')
		
		t = GeoIp_Scanner.GeoIPQueryThread( self.dbQueue, self.taskQueue, self.prefix, 
			self.cityDbPath , self.cityDbDatPath, self.cityDbDatPath_backup, self.maxmind_url)
		t.setDaemon(True)
		t.start()
		
		super(GeoIPScanner, self).waitingForQueuesToJoin()
# %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
# %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
# %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
		
# this depends totally on ones setup
def domainsToDb(path_to_src, path_to_domain_lists):
	main_config_file_loc = os.path.join(path_to_src, "global.config")
	initDomains = DomainHandler.InitialDomainAdd(main_config_file_loc)
	
	# Write the blacklisted domains to the DB
	bl_domains_loc = os.path.join(path_to_src, "blacklisted_domains.txt")
	initDomains.processBlacklistedDomains(bl_domains_loc)
	
	# Add domain files to the DB
	alexaTop1k = os.path.join(path_to_domain_lists, "alexaTop1k.txt")
	deAlexaTop1k = os.path.join(path_to_domain_lists, "deAlexaTop1k.txt")
	randomAlexaTop1k = os.path.join(path_to_domain_lists, "randomAlexaTop1k.txt")
	randMalwareList = os.path.join(path_to_domain_lists, "randMalwareList.txt")
	malwareList_2012_10 = os.path.join(path_to_domain_lists, "malware_domainlist_2012_10.txt")
	
	initDomains.processDomainFileToDB(alexaTop1k)
	print "Done with Alexa Top 1k"
	initDomains.processDomainFileToDB(deAlexaTop1k)
	print "Done with Alexa -DE- Top 1k"
	initDomains.processDomainFileToDB(randomAlexaTop1k)
	print "Done with Random Alexa Top 1k"
	initDomains.processDomainFileToDB(randMalwareList)
	print "Done with Rand Malware"
	initDomains.processDomainFileToDB(malwareList_2012_10)
	print "Done with malwareList_2012_10"


# %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
#
# %%%%%%%%% MAIN 
#
# %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

if __name__ == '__main__':
	path_to_src = "/home/kulzer/ma_rkulz/src/"
	path_to_domain_lists = "/home/kulzer/ma_rkulz/scans/second_series/"
	
	# Set up new dir for scan log files
	"""
	path_to_curr_logs = os.path.join(path_to_src, 'logs/scan5')
	if not os.path.exists(path_to_curr_logs):
		 os.makedirs(path_to_curr_logs) 
	"""
	
	#subprocess.call(['make -C /home/kulzer/ma_rkulz/src/sql_config/ tables TUM_DB=asn TUM_SCHEMA=scan5'])

	# Fill the domains in the DB
	# TODO enable if neccessary
	#domainsToDb(path_to_src, path_to_domain_lists)
	
	main_config_file_loc = os.path.join(path_to_src, "global.config")
	
	#print("Starting of with ASN scanner")
	#asnScanner = AsnScanner(main_config_file_loc)
	#asnScanner.start_ASN_Scan()
	
	#print("Starting GeoIP scanner")
	#geoipScanner = GeoIPScanner(main_config_file_loc)
	#geoipScanner.start_GeoIP_Scan()
	
	#print("Next scanner is whois")
	#whoisScanner = WhoisScanner(main_config_file_loc)
	#whoisScanner.start_Whois_Scan()
	
	#print("Now fire up nmap")
	# TODO figure out how to start nmapScanner as root !!!
	#nmapScanner = NmapScanner(main_config_file_loc)
	#nmapScanner.start_Nmap_Scan()
	
	#print("Finally DNS")
	dnsScanner = DnsScanner(main_config_file_loc)
	dnsScanner.start_Dns_Scan()

	print("Done")
