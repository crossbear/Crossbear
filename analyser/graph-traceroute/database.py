#!/usr/bin/python

from ConfigParser import SafeConfigParser
import psycopg2
import psycopg2.extras


class DB(object):
    def __init__(self, config_file):
        self.config = SafeConfigParser()
        self.config.read(config_file)
        self.crossbeardb = psycopg2.connect(
            host = self.config.get("crossbeardb", "host"),
            user = self.config.get("crossbeardb", "user"),
            database = self.config.get("crossbeardb", "dbname"),
            password = self.config.get("crossbeardb", "password"))

        self.analysisdb = psycopg2.connect(
            host = self.config.get("analysisdb", "host"),
            user = self.config.get("analysisdb", "user"),
            database = self.config.get("analysisdb", "dbname"),
            password = self.config.get("analysisdb", "password"))
        
    def traces(self, huntingtaskid):
        tracecursor = self.crossbeardb.cursor(cursor_factory = psycopg2.extras.DictCursor)
        geocursor = self.analysisdb.cursor(cursor_factory = psycopg2.extras.DictCursor)
        ascursor = self.analysisdb.cursor(cursor_factory = psycopg2.extras.DictCursor)
        # select htr.trace, co.observertype, sc.sha1derhash  from huntingtaskresults as htr full join certobservations as co on htr.observation = co.id full join servercerts as sc on co.certid = sc.id where huntingtaskid = %s'
        tracecursor.execute("SELECT htr.trace, co.observertype, sc.sha1derhash as hash from huntingtaskresults as htr full join " +
                       "certobservations as co on htr.observation = co.id full join servercerts as sc on co.certid = " +
                       "sc.id where huntingtaskid = %s", (huntingtaskid,))
        for row in tracecursor:
            t = Trace(row['observertype'], row['hash'])
            for line in row['trace'].split("\n"):
                te = TraceElem()
                for ip in line.split("|"):
                    geocursor.execute("SELECT city, country_code FROM geo_results WHERE ip = %s", (ip,))
                    ascursor.execute("SELECT asn FROM asn_results WHERE ip = %s", (ip,))
                    georesult = geocursor.fetchone()
                    asresult = ascursor.fetchone()
                    if georesult == None or asresult == None:
                        print "Warning: No geo or as number information for IP %s" % (ip,)
                        te.add_ip(ip, None, None)
                    else:
                        te.add_ip(ip, asresult["asn"], georesult["country_code"])

                t.add_trace_elem(te)
            yield t
        geocursor.close()
        ascursor.close()
        tracecursor.close()

class HuntingTaskResults(object):
    
    def __init__(self, traces):
        self.traces = traces

    def traces(self):
        return self.traces
    
class Trace(object):
    
    def __init__(self, type, hash):
        # A list of lists of IP addresses
        self.trace = []
        self.type = type
        self.hash = hash
        
    def add_trace_elem(self,elem):
        self.trace.append(elem)

    def trace_elems(self):
        return self.trace

    def trace_elem(self, index):
        return self.trace[index]

    def hash(self):
        return self.hash

    def type(self):
        return self.type

    def __str__(self):
        trace = "\n\t".join([s.__str__() for s in self.trace])
        return "Trace(trace=%s, type=%s, hash=%s)" % (trace, self.type, self.hash)

class TraceElem(object):
    
    def __init__(self):
        self.ip = []
        self.asn = {}
        self.geo = {}

    def add_ip(self,ip, asn, geo):
        self.ip.append(ip)
        self.asn[ip] = asn;
        self.geo[ip] = geo;

    def geo(self, ip):
        return self.geo[ip]

    def asn(self, ip):
        return self.asn[ip]

    def ips(self):
        return self.ip

    def __str__(self):
        return "TraceElem(ips=[%s], asn={%s}, geo={%s})" % (self.ip, self.asn, self.geo)

if __name__ == "__main__":
    db = DB("analyser.config")
    for i in db.traces(1):
        print i
