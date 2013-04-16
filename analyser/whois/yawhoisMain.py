
import Queue
import threading
import logging

from ConfigParser import SafeConfigParser
from db import DbPool
from StorageThread import StorageThread
from psycopg2 import IntegrityError
from yawhois import yawhois


class WhoisQueryThread(threading.Thread):

	def __init__(self, taskQueue, dbQueue, prefix):
		"""Create scanning thread.
		
		@param taskQueue: Queue.Queue containing domains to scan as strings
		@param dbQueue: Queue.Queue for passing things to store to StorageThread
		@param opts: instance of DnsConfigOptions
		@param prefix: prefix of schema
		"""
		self.taskQueue = taskQueue
		self.dbQueue = dbQueue
		self.prefix = prefix

		threading.Thread.__init__(self)

	def run(self):
		while True:
			domain = self.taskQueue.get()
			
			try:
				w = yawhois.yawhois(domain)
				
				sql = "INSERT INTO %swhois " % self.prefix
				sql = sql + """(fqdn, nserver, update_date, create_date, expiration_date)
				VALUES ("""+self.prefix+"""insert_unique_domain(%s), %s, %s, %s)
				"""
				
				sql_data = ( domain, w.get('soa'), w.get('update_date'),
				       w.get('create_date'), w.get('expiration_date') )
				
				self.dbQueue.put((sql, sql_data))
			except:
				logging.exception("Fetching-Error for %s", domain)
			finally:
				self.taskQueue.task_done()
				logging.info("Finished scanning domain %s", domain)


if __name__ == '__main__':
	if len(sys.argv) != 3: 
		print >> sys.stderr, "ERROR: usage: <domain_file> <config>" 
		sys.exit(1)
		
	domainFilename = sys.argv[1]
	domainFile = file(domainFilename)
	mainConfig = SafeConfigParser()
	mainConfig.read(sys.argv[2])

	threadCount = mainConfig.getint("processing", "scan_threads")

	# prefix/schema to use in DB:
	prefix = ""
	if mainConfig.has_option("database", "prefix"):
		prefix = mainConfig.get("database", "prefix")
	
	sourceEncoding = "utf-8"
	
	#one DB connection per storage thread
	storageThreads = mainConfig.getint("processing", "storage_threads")
	db = DbPool(mainConfig, max_connections=storageThreads)
	

	""" TODO

	logfile = mainConfig.get("log", "logfile")
	loglevel = convertLoglevel(mainConfig.get("log", "loglevel"))
	if logfile == "-":
		logging.basicConfig(stream=sys.stderr, level=loglevel,
			format="%(asctime)s %(levelname)s %(message)s [%(pathname)s:%(lineno)d]")
	else:
		logging.basicConfig(filename=logfile, level=loglevel,
			format="%(asctime)s %(levelname)s %(message)s [%(pathname)s:%(lineno)d]")

	logging.info("Starting scan of domains in file %s using %d threads.", domainFilename, threadCount)
	"""
	
	taskQueue = Queue.Queue(5000)
	dbQueue = Queue.Queue(500)
	
	for i in range(threadCount):
		t = WhoisQueryThread(taskQueue, dbQueue, prefix)
		t.setDaemon(True)
		t.start()
	
	for i in range(storageThreads):
		t = StorageThread(db, dbQueue)
		t.setDaemon(True)
		t.start()
	
	startTime = time.time()
	domainCount = 0
	
	for line in domainFile:
		#automatically punycode-encode any IDN domains
		try:
			domainEncoded = line.rstrip()
			domain = domainEncoded.decode(sourceEncoding).encode("idna")
		except ValueError: #UnicodeDecodeError etc. are subclasses of ValueError
			logging.error("Could not decode string '%s' from encoding %s",
				domainEncoded, sourceEncoding)
			continue
		taskQueue.put(domain)
		domainCount += 1
		
	taskQueue.join()
	
	logging.info("Waiting for storage threads to finish")
	dbQueue.join()
	logging.info("Fetch of whois requests for %d domains took %.2f seconds", domainCount, time.time() - startTime)