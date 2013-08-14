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
        traces = []
        tracecursor = self.crossbeardb.cursor(cursor_factory = psycopg2.extras.DictCursor)
        #TODO: Add WHOIS information.
        geocursor = self.analysisdb.cursor(cursor_factory = psycopg2.extras.DictCursor)
        ascursor = self.analysisdb.cursor(cursor_factory = psycopg2.extras.DictCursor)
        tracecursor.execute("SELECT htr.trace, co.observertype, sc.sha1derhash as hash from huntingtaskresults as htr full join " +
                       "certobservations as co on htr.observation = co.id full join servercerts as sc on co.certid = " +
                       "sc.id where huntingtaskid = %s", (huntingtaskid,))
        for row in tracecursor:
            trace = Trace(row['observertype'], row['hash'])
            traceval = row['trace'].split("\n")
            for line in traceval:
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
                trace.add_trace_elem(te)
            traces.append(trace)
        geocursor.close()
        ascursor.close()
        tracecursor.close()
        return HuntingTaskResults(traces)

class HuntingTaskResults(object):
    
    def __init__(self, traces):
        self.m_traces = traces

    def traces(self):
        return self.m_traces
    
class Trace(object):
    
    def __init__(self, type, hash):
        # A list of lists of IP addresses
        self.m_trace = []
        self.m_type = type
        self.m_hash = hash
        
    def add_trace_elem(self,elem):
        self.m_trace.append(elem)

    def trace_elems(self):
        return self.m_trace

    def trace_elem(self, index):
        return self.m_trace[index]

    def hash(self):
        return self.m_hash

    def type(self):
        return self.m_type

    def __str__(self):
        trace = "\n\t".join([s.__str__() for s in self.m_trace])
        return "Trace(trace=%s, type=%s, hash=%s)" % (trace, self.m_type, self.m_hash)

class TraceElem(object):

    def __init__(self, ip = None, asn = None, geo = None):
        if ip == None:
            self.m_ip = []
        else:
            self.m_ip = ip
        if asn == None:
            self.m_asn = {}
        else:
            self.m_asn = asn
        if geo == None:
            self.m_geo = {}
        else:
            self.m_geo = geo

    def add_ip(self,ip, asn, geo):
        self.m_ip.append(ip)
        self.m_asn[ip] = asn;
        self.m_geo[ip] = geo;

    def geo(self, ip):
        return self.m_geo[ip]

    def asn(self, ip):
        return self.m_asn[ip]

    def ips(self):
        return self.m_ip

    def __str__(self):
        return "TraceElem(ips=%s, asn=%s, geo=%s)" % (self.m_ip, self.m_asn, self.m_geo)

if __name__ == "__main__":
    db = DB("analyser.config")
    result = db.traces(1)
    for trace in result.traces():
        print trace
