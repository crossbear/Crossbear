#!/usr/bin/python

from ConfigParser import SafeConfigParser
import psycopg2
import psycopg2.extras


class DB(object):
    def __init__(self, config_file):
        self.config = SafeConfigParser()
        self.config.read(config_file)
        self.tracedb = psycopg2.connect(
            host = self.config.get("tracedb", "host"),
            user = self.config.get("tracedb", "user"),
            database = self.config.get("tracedb", "dbname"),
            password = self.config.get("tracedb", "password"))
        
    def traces(self, huntingtaskid):
        cursor = self.tracedb.cursor(cursor_factory = psycopg2.extras.DictCursor)
        cursor.execute("SELECT trace FROM huntingtaskresults WHERE huntingtaskid = %s;", (huntingtaskid,))
        for row in cursor:
            result = []
            for line in row['trace'].split("\n"):
                result.append(line.split("|"))
            yield result
        cursor.close()


class Trace(object):
    
    def __init__(self):
        # A list of lists of IP addresses
        self.ip_trace = []
        # A list of lists of AS numbers.
        self.as_trace = []
        # If this is a victim trace or a regular trace
        self.attacked = False
        
        
