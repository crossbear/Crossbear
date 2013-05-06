#   This file is part of DNS Scraper and now also used here in the rest of my Master' thesis
#
#   Copyright (C) 2012 Ondrej Mikle, CZ.NIC Labs
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


from psycopg2.extras import DictCursor

#following ugliness is workaround for psycopg < 2.2.2 messing with logging system
try:
	import logging
	tmp = logging.basicConfig
	logging.basicConfig = lambda **kwargs: None
	from psycopg2.pool import PersistentConnectionPool
	logging.basicConfig = tmp
except:
	raise


class DbPool(object):
	"""DB class that makes connection transparently. Thread-safe - every
	thread get its own database connection.
	"""

	def __init__(self, config, dbname, min_connections=1, max_connections=5):
		"""Configures the Db, connection is not created yet.
		
		@param config: instance of RawConfigParser or subclass.
		@param min_connections: minimum connections in pool
		@param max_connections: maximum allowed connections in pool
		"""

		self.host = config.get("database", "host")
		self.port = config.getint("database", "port")
		self.user = config.get("database", "user")
		self.password = config.get("database", "password")
		#self.db_name = config.get("database", "dbname")
		self.db_name = dbname
		self.min_connections = min_connections
		self.max_connections = max_connections

		self.pool = PersistentConnectionPool(
			minconn = self.min_connections,
			maxconn = self.max_connections,
			host = self.host,
			port = self.port,
			user = self.user,
			password = self.password,
			database = self.db_name)

	def cursor(self, **kwargs):
		"""Creates and returns cursor for current thread's connection.
		Cursor is a "dict" cursor, so you can access the columns by
		names (not just indices), e.g.:

		cursor.execute("SELECT id, name FROM ... WHERE ...", sql_args)
		row = cursor.fetchone()
		id = row['id']
		
		Server-side cursors (named cursors) should be closed explicitly.
		
		@param kwargs: currently string parameter 'name' is supported.
		Named cursors are for server-side cursors, which
		are useful when fetching result of a large query via fetchmany()
		method. See http://initd.org/psycopg/docs/usage.html#server-side-cursors
		"""
		return self.connection().cursor(cursor_factory=DictCursor, **kwargs)
	
	def connection(self):
		"""Return connection for this thread"""
		return self.pool.getconn()

	def commit(self):
		"""Commit all the commands in this transaction in this thread's
		connection. If errors (e.g. duplicate key) arose, this will
		cause transaction rollback.
		"""
		self.connection().commit()

	def rollback(self):
		"""Rollback last transaction on this thread's connection"""
		self.connection().rollback()
	
	def putconn(self):
		"""Put back connection used by this thread. Necessary upon finishing of
		spawned threads, otherwise new threads won't get connection if the pool
		is depleted."""
		conn = self.connection()
		self.pool.putconn(conn)
	
	def close(self):
		"""Close connection."""
		self.connection().close()


