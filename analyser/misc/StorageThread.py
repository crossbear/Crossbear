import Queue
import threading
import logging
import sys

import psycopg2

class StorageThread(threading.Thread):
	"""Thread taking sql/sql_data from queue and executing it for storage in DB"""

	def __init__(self, db, dbQueue):
		"""Create storage thread.
		
		@param db: database connection pool, instance of db.DbPool
		@param dbQueue: instance of Queue.Queue that stores (sql,
		sql_data) tuples to be executed
		"""
		self.db = db
		self.dbQueue = dbQueue
		
		threading.Thread.__init__(self)

	def run(self):
		conn = self.db.connection()
		while True:
			sqlTuple = self.dbQueue.get()
			lastIntegrityError = None
			sql = ""
			sql_data = ""
			
			try:
				cursor = conn.cursor()
				sql, sql_data = sqlTuple
				cursor.execute(sql, sql_data)
			
			except psycopg2.IntegrityError:
				error_msg = "IntegrityError: failed attempt to insert '%s' " % sql_data 
				error_msg += "with CMD: \n" + sql +"\n"
				logging.exception(error_msg)
			
			except psycopg2.DataError:
				logging.exception("DataError: failed to convert data for %s", sql_data)
					
			except Exception:
				logging.exception("Failed to execute cmd %s with %s", sql, sql_data)
					
			finally:
				conn.commit()
				
			self.dbQueue.task_done()