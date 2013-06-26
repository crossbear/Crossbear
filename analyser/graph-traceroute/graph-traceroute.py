#!/usr/bin/python


import psycopg2
import psycopg2.extras
import pygraphviz as pgv
from sys import argv
from ConfigParser import SafeConfigParser

class TraceDB(object):
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

if len(argv) != 3:
    print "Plese call with \"graph-traceroute.py <config file> <huntingtask id>\"."
    exit(1)

tdb = TraceDB(argv[1])
g = pgv.AGraph(directed = True)

for singletrace in tdb.traces(argv[2]):
    prevnodes = []
    for nextnodes in singletrace:
        for node in nextnodes:
            for prevnode in prevnodes:
                g.add_edge(prevnode,node)
        prevnodes = nextnodes

g.layout(prog = "dot")
g.draw("test.png")

            
