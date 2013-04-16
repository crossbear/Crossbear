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
import PyASN
import Queue
import threading

class AsnStats(object):
	def __init__(self):
		self.diff_ips = []
		self.diff_asns = []
		self.nr_ips_same_asn = 1
		# following value is used as boolean value
		self.all_ips_same_asn = 0
	
	def calcStats(self, ip, asn):
		"""
			Calculates IP and ASN statistics
		"""
		if asn not in self.diff_asns:
			self.diff_asns.append(asn)
		else:
			self.nr_ips_same_asn += 1
			
		if ip not in self.diff_ips:
			self.diff_ips.append(ip)
		
class AsnStore(object):
	def __init__(self, dbQueue, prefix):
		"""
			@param dbQueue: Queue.Queue for passing things to store to StorageThread
			@param prefix: prefix of schema
		"""
		self.dbQueue = dbQueue
		self.prefix = prefix
	
	def storeASN(self, res, asnStats):
		""" Puts results (res) in storeage queue
			@param res: Result dict  --> res = {"<domain_name>": {ip:asn, ip2:asn2, ... } }
			@param asnStats: holds statistical values
		"""
		sql = "INSERT INTO %sdomains " % self.prefix
		sql += "(fqdn, scan_time) VALUES (%s, (SELECT TIMESTAMP 'now'))"
		
		# there should be just one domain name per res dict
		domain = res.keys()[-1]
		
		# put domain 
		try:
			self.dbQueue.put( (sql, (domain,)) )
		except:
			logging.error("Could not store domain: %s", domain)
		
		sql = "INSERT INTO %sasn " % self.prefix
		sql = sql + """(host_id, ip, asn) 
					VALUES ("""+self.prefix+"""insert_unique_domain(%s), %s, %s) """
		
		for ip, asn in res[domain].items():
			asnStats.calcStats(ip, asn)
			try:
				sql_data = (domain, ip, asn)
				self.dbQueue.put( (sql, sql_data) )
			except:
				logging.error("Could not store ip: %s", ip)

	def storeEval(self, domain, asnStats):
		"""
			Gathers statistical data and store it in 
			the eval_asn table within the corresponding schema.
		"""
		sql = "INSERT INTO %seval_asn " % self.prefix
		sql = sql + """(host_id, nr_diff_asns, nr_diff_ips, 
				nr_ips_same_asn, all_ips_same_asn) 
				VALUES ("""+self.prefix+"""insert_unique_domain(%s),
				%s, %s, %s, %s) """
				
		nr_diff_asns = len(asnStats.diff_asns)
		nr_diff_ips = len(asnStats.diff_ips)
		if nr_diff_asns == 1:
			asnStats.all_ips_same_asn = 1
			
		sql_data = (domain, nr_diff_asns, nr_diff_ips, asnStats.nr_ips_same_asn, 
				asnStats.all_ips_same_asn)
		
		try:
			self.dbQueue.put( (sql, sql_data) )
		except: 
			logging.error("Could not store evaluation data for domain %s", domain)
	
class AsnQueryThread(threading.Thread):
	def __init__(self, taskQueue, dbQueue, prefix, ipasndat_file_loc):
		"""
			@param pyASN: pyASN object to make the actual queries
		"""
		self.pyASN = PyASN.new(ipasndat_file_loc)
		self.dbQueue = dbQueue
		self.taskQueue = taskQueue
		self.prefix = prefix
		
		threading.Thread.__init__(self)
		
	def run(self):
		asnStore = AsnStore(self.dbQueue, self.prefix)
		
		while True:
			domain, ip_list_for_domain = self.taskQueue.get()
			asnStats = AsnStats()
			
			try:
				res = {domain: {}}
				
				for ip in ip_list_for_domain:
					res[domain][ip] = self.pyASN.Lookup(ip)
				
				asnStore.storeASN(res, asnStats)
				asnStore.storeEval(domain, asnStats)
				
				asnStats = None
					
			except:
				logging.exception("Fetching-Error for %s", domain)
				
			finally:
				self.taskQueue.task_done()