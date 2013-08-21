#!/usr/bin/python

from ConfigParser import SafeConfigParser
import psycopg2
import warnings
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
        
    def get_huntingtask(self, huntingtaskid):
        htcursor = self.crossbeardb.cursor(cursor_factory = psycopg2.extras.DictCursor)
        htcursor.execute("select targethostname, targetip, targetport, timeofcreation from huntingtasks where id = %s", (huntingtaskid,))
        row = htcursor.fetchone()
        result = HuntingTask(row['targethostname'], row['targetip'], row['targetport'], row['timeofcreation'])
        htcursor.close()
        return result

        # Beware: types is mutable! Look up "python mutable defaults"
    def get_certs_by_hostname(self, server, port, types = ("CrossbearServer", "CrossbearCVR", "CrossbearHunter")):
        result = []
        certcursor = self.crossbeardb.cursor(cursor_factory = psycopg2.extras.DictCursor)
        certcursor.execute("select co.observertype, sc.sha1derhash from certobservations as co, servercerts as sc where sc.id = co.certid and serverhostport = %s and co.observertype in %s", ("%s:%s" % (server, port),types))

        for r in certcursor:
            result.append(Certificate(r["sha1derhash"], r["observertype"]))
        certcursor.close()
        return result

    def get_geo_information(self, ip):
        geocursor = self.analysisdb.cursor(cursor_factory = psycopg2.extras.DictCursor)
        geocursor.execute("SELECT city, country_code FROM geo_results WHERE ip = %s", (ip,))
        # Fetch just one for now. Don't know how to deal with more than one result
        row = geocursor.fetchone()
        geocursor.close()
        return "%s, %s" % (row["city"], row["country_code"])

    def get_asn_information(self, ip):
        ascursor = self.analysisdb.cursor(cursor_factory = psycopg2.extras.DictCursor)
        ascursor.execute("SELECT asn FROM asn_results WHERE ip = %s", (ip,))
        row = ascursor.fetchone()
        ascursor.close()
        if row['asn'] == None:
            warnings.warn("No ASN data for ip %s" % ip)
            return "-1"
        return "%d" % (row["asn"],)
        
    def get_trace_information(self, trace):
        result = Trace()
        for line in trace.split("\n"):
            te = TraceElem()
            for ip in line.split("|"):
                geo = self.get_geo_information(ip)
                asn = self.get_asn_information(ip)
                te.add_ip(ip, asn, geo)
            result.add_trace_elem(te)
        return result
                
    def get_huntingtaskresults(self,huntingtaskid):
        result = []
        htrcursor = self.crossbeardb.cursor(cursor_factory = psycopg2.extras.DictCursor)
        htrcursor.execute("select htr.trace, sc.sha1derhash as hash from huntingtaskresults as " +
                          "htr full join certobservations as co on htr.observation = co.id full join servercerts " +
                          "as sc on co.certid = sc.id where huntingtaskid = %s", (huntingtaskid,))
        for r in htrcursor:
            trace = self.get_trace_information(r["trace"])
            # Certificate type can only be hunter, so we fake it here.
            result.append(HuntingTaskResult(trace, Certificate(r['hash'], "CrossbearHunter")))
        htrcursor.close()
        return result
            
    def traces(self, huntingtaskid):
        ht = self.get_huntingtask(huntingtaskid)
        certs = self.get_certs_by_hostname(ht.hostname(), ht.port(), ("CrossbearServer", "CrossbearCVR"))
        ht.certificates(certs)
        results = self.get_huntingtaskresults(huntingtaskid)
        ht.results(results)
        return ht
        
class Certificate(object):
    
    def __init__(self, hash, type):
        self.m_hash = hash
        self.m_type = type

    def type(self):
        return self.m_type

    def hash(self):
        return self.m_hash

    def __repr__(self):
        return "Certificate(type=%s, hash=%s)" % (self.m_type, self.m_hash)
        
class HuntingTask(object):
    def __init__(self, hostname, ip, port, creation):
        self.m_hostname = hostname
        self.m_ip = ip
        self.m_port = port
        self.m_creation = creation
        self.m_certificates = []
        self.m_hunting_results = []

    def certificates(self, arg = None):
        if arg != None:
            self.m_certificates = arg
        else:
            return self.m_certificates

    def results(self, arg = None):
        if arg != None:
            self.m_hunting_results = arg
        else:
            return self.m_hunting_results

    def hostname(self):
        return self.m_hostname
        
    def ip(self):
        return self.m_ip
        
    def port(self):
        return self.m_port

    def creation(self):
        return self.m_creation

    def __repr__(self):
        return "HuntingTask(hostname=%s, ip=%s, port=%s, creation=%s, results=%s, certificates=%s)" % (
            self.m_hostname, self.m_ip, self.m_port,
            self.m_creation, self.m_hunting_results,
            "\n".join([c.__repr__() for c in self.m_certificates]))

class HuntingTaskResult(object):
    
    def __init__(self, trace, cert):
        self.m_trace = trace
        self.m_cert = cert

    def certificate(self):
        return self.m_cert

    def trace(self):
        return self.m_trace

    def __repr__(self):
        return "HuntingTaskResults(cert=%s, trace=%s)" % (self.m_cert,self.m_trace)
        
class Trace(object):
    
    def __init__(self):
        # A list of lists of IP addresses
        self.m_trace = []
    
    def add_trace_elem(self,elem):
        self.m_trace.append(elem)

    def trace_elems(self):
        return self.m_trace

    def trace_elem(self, index):
        return self.m_trace[index]

    def __repr__(self):
        trace = "\n\t".join([s.__repr__() for s in self.m_trace])
        return "Trace(trace=%s)" % (trace,)

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

    def __repr__(self):
        return "TraceElem(ips=%s, asn=%s, geo=%s)" % (self.m_ip, self.m_asn, self.m_geo)

if __name__ == "__main__":
    db = DB("analyser.config")
    result = db.traces(1)
    print result
