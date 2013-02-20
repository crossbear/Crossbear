import psycopg2
import subprocess
import re
import logging

re_akid = re.compile("X509v3 Authority Key Identifier:.*\n.*keyid:(.*)")
re_issuer = re.compile("(Issuer: .*)")

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
    hashcert = rows[0]
    cert = rows[1]

    p = subprocess.Popen(["openssl", "x509", "-noout", "-text"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.stdin.write(cert)
    p.stdin.close()
    res = p.stdout.read()
    resError = p.stderr.read()
    p.wait()
    p.stdout.close()
    p.stderr.close()

    resOpensslError = re_opensslError.search(resError)
    if resOpensslError != None:
        logging.error("Critical error for certificate " + hashcert)
        logging.error(resError)
        return None

    issuer = getIssuer(res)
    aki = getAKID(res)
    return (issuer, aki)


def main():
    issuerInfo = "issuer_info"    
    connectString = "dbname='crossbeartesting' user='postgres' host='localhost'"
    conn = psycopg2.connect(connectString)
    c = conn.cursor()
    up = conn.cursor()

    qlSelectCerts = "SELECT pemraw FROM servercerts"
    try:
        c.execute(sqlSelectCerts)
    except Exception, e:
        logging.error("SELECT FF OIDs failed.")
        logging.error(e)
        sys.exit(-1)
    conn.commit()

    for row in c:
    	(issuer, aki) = getIssuerAndAKI(row)
    	if(None in (issuer,aki)):
            # TODO: add logging
            print "problem.."
            continue
    	
        # sqlInsertResults = "INSERT INTO issuer_info (issuing_ca, aki) VALUES ('"+issuer+"', '"+aki+"')"
        sqlInsertResults = "INSERT INTO issuer_info (issuing_ca, aki) VALUES (%s, %s)"
    	try:
            up.execute(sqlInsertResults, (issuer, aki))
        except Exception, e:
            logging.error("SELECT FF OIDs failed.")
            logging.error(e)
            continue

        conn.commit()
if __name__ == "__main__":
	main()
