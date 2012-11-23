import psycopg2
import subprocess
import re
import logging
import getpass
import sys
from ConfigParser import SafeConfigParser

#configfile = home + "/pki_crawl.conf"
#confparser = SafeConfigParser()
#confparser.read(configfile)
#dbname = confparser.get('database', 'dbname')
#username = confparser.get('database', 'username')
#dbhost = confparser.get('database', 'host')
#password = confparser.get('database', 'password')
#logpath = confparser.get('log', 'logpath')
#loglevel = "logging." + confparser.get('log', 'loglevel')

# TODO
# LOG_FILENAME = logpath + "/readIssuersAKI_" + date + ".log"
# logging.basicConfig(filename=LOG_FILENAME, level=loglevel, filemode='w')

re_akid = re.compile("X509v3 Authority Key Identifier:.*\n.*keyid:(.*)")
re_issuer = re.compile("(Issuer: .*)")
re_opensslError = re.compile(":error:")

def simpleKeyValue(regex, res):
    resultGroup = regex.search(res)
    if (resultGroup != None):
        valueGrouped = resultGroup.group(0)
        value = valueGrouped.split(": ", 1)[1]
        return value.lstrip()
    else:
        return "not set"

def getIssuer(res):
    global re_issuer
    issuer = simpleKeyValue(re_issuer, res)
    logging.info("Issuer: " + issuer)
    return issuer

def getAKID(res):
    global re_akid
    resultAKID = re_akid.search(res)
    akid = None
    if (resultAKID != None):
        akid = resultAKID.group(1)
        akid = akid.lstrip().rstrip()
    return akid

def getIssuerAndAKI(rows):
    # print rows, len(rows)
    ID = rows[0]
    cert = rows[1]
    
    p = subprocess.Popen(["openssl", "x509", "-noout", "-text"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.stdin.write(cert)
    p.stdin.close()
    res = p.stdout.read()
    resError = p.stderr.read()
    p.wait()
    p.stdout.close()
    p.stderr.close()
    # print res
    resOpensslError = re_opensslError.search(resError)
    if resOpensslError != None:
        logging.error("Critical error for certificate " + ID)
        logging.error(resError)
        return None

    issuer = getIssuer(res)
    aki = getAKID(res)
    # if not aki:
    #     logging.error(res)
    return (issuer, aki, ID)


def main():
    issuerInfo = "issuer_info"    
    passwd = getpass.getpass()
    connectString = "dbname='crossbeartesting' user='postgres' host='localhost' password='"+passwd+"'"
    conn = psycopg2.connect(connectString)
    c = conn.cursor()
    up = conn.cursor()

    sqlSelectCerts = "SELECT id, pemraw FROM servercerts;"
    try:
        c.execute(sqlSelectCerts)#, ('id', 'pemraw'))
    except Exception, e:
        logging.error("SELECT FF OIDs failed.")
        logging.error(e)
        sys.exit(-1)
    conn.commit()
    
    for row in c:
    	(issuer, aki,ID) = getIssuerAndAKI(row)
    	if(None in (ID, issuer)):
            print "ERROR: ID = "+str(ID)+" Issuer = "+str(issuer)
            # TODO: add logging
            print "problem.."
            continue
    	if not aki:
            aki = "None"
        # sqlInsertResults = "INSERT INTO issuer_info (issuing_ca, aki) VALUES ('"+issuer+"', '"+aki+"')"
        sqlInsertResults = "INSERT INTO issuer_info (issuing_ca, aki, id) VALUES (%s, %s, %s)"
    	try:
            up.execute(sqlInsertResults, (issuer, aki,ID))
        except Exception, e:
            logging.error("SELECT FF OIDs failed.")
            logging.error(e)
            continue

        conn.commit()
if __name__ == "__main__":
	main()
