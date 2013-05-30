#!/usr/bin/python

################################################################
# This script extracts relevant data from certificates from
# Crossbear results.
# It is almost identical to the one used by the SSL Landscape.
###############################################################

import psycopg2
import sys
import os
import subprocess
import re
import time
import logging
from ConfigParser import SafeConfigParser

def printUsage():
  print """
  Usage: process_server_certs.py <tablename>
    with <tablename> either "servercerts" or "chaincerts"
  """
  sys.exit(-1)

if ( len(sys.argv) != 2):
  printUsage()

tablename = sys.argv[1]

if tablename != "servercerts" and tablename != "chaincerts":
  printUsage()

date = time.strftime("%Y-%m-%d-%H:%M")
home = os.environ["HOME"]

configfile = "cb_analysis.conf"
confparser = SafeConfigParser()
confparser.read(configfile)
db_name = confparser.get('database', 'dbname')
db_username = confparser.get('database', 'username')
dbhost = confparser.get('database', 'host')
db_password = confparser.get('database', 'password')
logpath = confparser.get('log', 'logpath')

# Database
conn = None
cursor = None

# Logger
LOG_FILENAME = home + "/process_server_certs_" + tablename + "_" + date + ".log"
logging.basicConfig(filename=LOG_FILENAME, level=logging.DEBUG, filemode='w')


#############################################################
# REGEXES
#############################################################
re_sigAlgorithm = re.compile("(Signature Algorithm: .*)")
re_version = re.compile("(Version: .*)")
re_serialNumberBreak = re.compile("(Serial Number:\n.*)", re.MULTILINE)
re_serialNumberNoBreak = re.compile("(Serial Number:.*\n)", re.MULTILINE)
re_issuer = re.compile("(Issuer: .*)")
re_subject = re.compile("(Subject: .*)")
re_notBefore = re.compile("(Not Before: .*)")
re_notAfter = re.compile("(Not After : .*)")

re_pkAlgorithm = re.compile("(Public Key Algorithm: .*)")
re_pkLength = re.compile("Public Key: \(.*\)")
# this will get the modulus, but we need to strip all whitespaces, too
re_pkModulus = re.compile("Modulus.*bit\):(.*)Exponent", re.DOTALL)
# this will get the exponent, but we need to strip whitespaces left and right
re_pkExponent = re.compile("Exponent:(.*)")

re_caFlagTrue = re.compile("CA:TRUE")
re_caFlagFalse = re.compile("CA:FALSE")

re_subjAltName = re.compile("(Subject Alternative Name:.*\n*.*)")

re_akid = re.compile("X509v3 Authority Key Identifier:.*\n.*keyid:(.*)")
re_skid = re.compile("X509v3 Subject Key Identifier:.*\n\s*(.*)")

re_opensslError = re.compile(":error:")

#############################################################

# Helper functions

#############################################################
def simpleKeyValue(regex, res):
    resultGroup = regex.search(res)
    if (resultGroup != None):
        valueGrouped = resultGroup.group(0)
        value = valueGrouped.split(": ", 1)[1]
        return value.lstrip()
    else:
        return "not set"



def iflogging(s):
  logging.info(s)
        

#############################################################
# The extractors start here
#############################################################



# 1) SignatureAlgorithm
# A cert contains sigAlgorithm usually at two positions:
# Before "Issuer" and at the end. Both are the same.
# We follow that assumption here and just check if "Signature Algorithm"
# occurs more often; in that case, we give a warning
def getSignatureAlgorithm(res):
    global re_sigAlgorithm
    resultSigAlgorithm = re_sigAlgorithm.findall(res)
    sigAlgo = "not set"
    if (resultSigAlgorithm != None):
        size = len(resultSigAlgorithm)
        if (size > 2):
            logging.info("WARNING: more than one signature algorithm seems to be used")
            for i in range(size):
                logging.info(resultSigAlgorithm[i])
        if (size == 0):
            logging.info("WARNING: no signature algorithm found in cert")
            return "BAD"
        
        sigAlgoTupel = resultSigAlgorithm[1].split(": ")
        if (len(sigAlgoTupel) != 2):
            logging.info("REGEXWARNING: sigAlgo seems to be bad.")
            return "BAD"
        sigAlgo = sigAlgoTupel[1].strip().rstrip()
    
    iflogging("Signature algorithm: " + sigAlgo)
    return sigAlgo



# 2) Version
def getVersion(res):
    global re_version
    resultVersion = re_version.search(res)
    version = "not set"
    if (resultVersion != None):
        versionTupel = resultVersion.group(1).split(": ")
        if (len(versionTupel) != 2):
            logging.info("REGEXWARNING: Version seems to be damaged.")
            return "BAD"               
        
        versionStringTupel = versionTupel[1].split(" (")
        
        if (len(versionStringTupel) != 2):
            logging.info("REGEXWARNING: Version string seems to be damaged.")
            return "BAD"
        
        version = versionStringTupel[0]
    iflogging("Version: " + version)
    return version


# 3) Serial number:
def getSerialNumber(res):
    global re_serialNumberBreak, re_serialNumberNoBreak
    serialNumber = "not set"
    resultSerialNumberBreak = re_serialNumberBreak.search(res)
    if (resultSerialNumberBreak != None):
        logging.info("1st type of serial number found:")
        serialNumberString = resultSerialNumberBreak.group(0)
        serialNumberTupel = serialNumberString.split("Serial Number:")
        if (len(serialNumberTupel) != 2):
            logging.info("REGEXWARNING: serial number seems to be damaged!")
            return "BAD"
        serialNumber = serialNumberTupel[1]
        serialNumber = serialNumber.lstrip().rstrip()
    else:
        logging.info("1st type of serial number not found, trying 2nd type:")
        resultSerialNumberNoBreak = re_serialNumberNoBreak.search(res)
        if (resultSerialNumberNoBreak != None):
            serialNumberString = resultSerialNumberNoBreak.group()
            serialNumberTupel = serialNumberString.split("Serial Number:")
            if (len(serialNumberTupel) != 2):
                logging.info("REGEXWARNING: serial number seems to be damaged!")
                return "BAD"
            serialNumber = serialNumberTupel[1]
            serialNumber = serialNumber.lstrip().rstrip()
    iflogging("Serial Number: " + serialNumber)
    return serialNumber



# 4) Issuer
def getIssuer(res):
    global re_issuer
    issuer = simpleKeyValue(re_issuer, res)
    iflogging("Issuer: " + issuer)
    return issuer



# 5) Not Before
def getNotBefore(res):
    global re_notBefore
    notBefore = simpleKeyValue(re_notBefore, res)
    # we may need to reformat this at some point
    # in any case, we want year and month
    # openssl output always seems to be the same, but we cannot be sure!
    timetuple = None
    if (notBefore != "not set"):
        try:
            timetuple = time.strptime(notBefore, "%b %d %H:%M:%S %Y %Z")
        except Exception, e:
            logging.info("WARNING: Time zone not set in Not Before!")
            try:
                timetuple = time.strptime(notBefore, "%b %d %H:%M:%S %Y")
            except Exception, e:
                logging.info("WARNING: Time in Not Before seems to be damaged!")
                return ("BAD", None)
    else:
        return ("not set", None)
    
    iflogging("Not Before: " + notBefore)
    return (notBefore, timetuple)




# 6) Not After
def getNotAfter(res):
    global re_notAfter
    notAfter = simpleKeyValue(re_notAfter, res)
    # we may need to reformat this at some point
    # in any case, we want year and month
    # openssl output always seems to be the same, but we cannot be sure!
    timetuple = None
    if (notAfter != "not set"):
        try:
            timetuple = time.strptime(notAfter, "%b %d %H:%M:%S %Y %Z")
        except Exception, e:
            logging.info("WARNING: Time zone not set in Not After!")
            try:
                timetuple = time.strptime(notAfter, "%b %d %H:%M:%S %Y")
            except Exception, e:    
                logging.info("WARNING: Time Not After seems to be damaged!")
                return ("BAD", None)
    else:
        return ("not set", None)
            
    iflogging("Not After: " + notAfter)
    return (notAfter, timetuple)




# 7) Public Key Algorithm
def getPKAlgorithm(res):
    global re_pkAlgorithm
    pkAlgorithm = simpleKeyValue(re_pkAlgorithm, res)
    iflogging("Public Key Algorithm: " + pkAlgorithm)
    return pkAlgorithm


# 7a) Public Key Modulus
def getPKModulus(res):
    global re_pkModulus
    pkModulus = "not set"
    resultPKModulus = re_pkModulus.search(res)
    if (resultPKModulus != None):
      modulus = re.sub(r'\s', '', resultPKModulus.group(1))
      return modulus
    else:
      logging.info("WARNING: Modulus not set in Public Key!")
      return "not set"

# 7b) Public Key Exponent
def getPKExponent(res):
    global re_PkExponent
    resultExponent = re_pkExponent.search(res)
    if (resultExponent != None):
      exponent = resultExponent.group(1).lstrip().rstrip()
      return exponent
    else:
      logging.info("WARNING: Exponent not set in Public Key!")
      return "not set"



# 8) Public Key Length
def getPKLength(res):
    global re_pkLength
    pkLength = simpleKeyValue(re_pkLength, res)
    if (pkLength == "not set"):
        logging.info("WARNING: PKLength not set")
        return "0"
    pkLength = pkLength.lstrip().rstrip()
    pkLength = pkLength.lstrip("(")
    pkLength = pkLength.rstrip(" bit )")
    iflogging("Public Key Length: " + pkLength)
    return pkLength





# 9) CA flag
def getCAFlag(res):
    global re_caFlagTrue, re_caFlagFalse
    resultCAFlagTrue = re_caFlagTrue.search(res)
    resultCAFlagFalse = re_caFlagFalse.search(res)
    
    caFlag = "not set"
    if ( (resultCAFlagFalse != None) and (resultCAFlagTrue != None) ):
        logging.info("WARNING: CA Flag verification produced bad result. Check it!")
    if (resultCAFlagTrue != None):
        caFlag = "TRUE"
    if (resultCAFlagFalse != None):
        caFlag = "FALSE"

    iflogging("CA flag: " + caFlag)
    return caFlag




# 13) Subject Alternative Name 
def getSubjAltName(res):
    global re_subjAltName
    resultSubjAltName = re_subjAltName.search(res)
    subjAltName = "not set"
    if (resultSubjAltName != None):
        resultSubjAltNameTupel = resultSubjAltName.group().split("Subject Alternative Name:")
        if (len(resultSubjAltNameTupel) != 2):
            logging.info("REGEXWARNING: subjAltName seems to be bad.")
            return "BAD"

        subjAltName = resultSubjAltNameTupel[1]
        subjAltName = subjAltName.lstrip().rstrip()
        
    iflogging("Subject alternative name: " + subjAltName)
    return subjAltName


# 14) get subject
def getSubject(res):
    global re_subject
    subject = simpleKeyValue(re_subject, res)
    iflogging("Subject: " + subject)
    return subject


# 15) get SKID and AKID
def getKIDs(res):
  global re_akid, re_skid
  
  skid = None
  akid = None
      
  resultSKID = re_skid.search(res)
  if (resultSKID != None):
    skid = resultSKID.group(1)
    skid = skid.lstrip().rstrip()

  resultAKID = re_akid.search(res)
  if (resultAKID != None):
    akid = resultAKID.group(1)
    akid = akid.lstrip().rstrip()

  return (akid, skid)




def main():
    global conn, cursor, tablenameCerts
    
    totalCount = 0
    
    print ""
    print ""
    print "Post-processing certificates..."

    # Open and init the DB
    # new interface
    conn = psycopg2.connect("dbname='" + db_name + "' user='" + db_username + "' host='localhost' password='" + db_password + "'")
    c = conn.cursor()
    loopCursor = conn.cursor()

    # Get lists of EV OIDs
    sqlSelectFFOids = "SELECT oid FROM " + tnEVFF + " WHERE oid != '0.0.0.0'"
    try:
      c.execute(sqlSelectFFOids)
    except Exception, e:
      logging.error("ERROR: SELECT FF OIDs failed.")
      logging.error(e)
      sys.exit(-1)
    conn.commit()

    rows = c.fetchall()
    for row in rows:
      ffOidList.append(row[0])


    sqlSelectMozOids = "SELECT oid FROM " + tnEVMoz + " WHERE oid != '0.0.0.0'"
    try:
      c.execute(sqlSelectMozOids)
    except Exception, e:
      logging.error("ERROR: SELECT Moz OIDs failed.")
      logging.error(e)
      sys.exit(-1)
    conn.commit()

    rows = c.fetchall()
    for row in rows:
      mozOidList.append(row[0])

    # CHANGED: select distinct certs to make it go faster
    loopCursor.execute("SELECT DISTINCT ON(hashcert) hashcert, cert FROM " + tablenameCerts)
    # This is if you need a second go because of some error in the first round:
    # UNTESTED
    #failedList = (...)
    #sqlExtension = "WHERE hashcert = '...' "
    #for entry in failedList:
    #  sqlExtension = sqlExtension + "OR hashcert = '" + entry + "' "
    #loopCursor.execute("SELECT hashcert,cert FROM " + tablenameCerts + " " + sqlExtension)

    sqlCounter = 0
    while True:
      rows = loopCursor.fetchone()
      if (rows == None):
        print "BREAKING OUT"
        # make sure to commit last SQL statements!
        try:
          conn.commit()
        except Exception, e:
          logging.error("ERROR: UPDATE operation failed when committing.")
          logging.error(e)
        break
      
      # print rows
      hashcert = rows[0]
      cert = rows[1]
           
      logging.info("######################################################")
      logging.info("Processing: " + hashcert)
            
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
        break

      # feed it to extractors
      sigAlgo = getSignatureAlgorithm(res)
      version = getVersion(res)
      serialNumber = getSerialNumber(res)
           
      issuer = getIssuer(res)
      subject = getSubject(res)
        
      #rewrite timestamp
      notBeforeList = getNotBefore(res)
      notBeforeString = notBeforeList[0]
      notBeforeValue = notBeforeList[1]
      if (notBeforeValue == None):
        notBeforeStamp = None
      else:
        notBeforeStamp = time.strftime("%Y-%m-%d %H:%M:%S", notBeforeValue)

      notAfterList = getNotAfter(res)
      notAfterString = notAfterList[0]
      notAfterValue = notAfterList[1]
      if (notAfterValue == None):
        notAfterStamp = None
      else:
        notAfterStamp = time.strftime("%Y-%m-%d %H:%M:%S", notAfterValue)
        
      pkAlgorithm = getPKAlgorithm(res)
      pkLength = getPKLength(res)
      pkModulus = getPKModulus(res)
      pkExponent = getPKExponent(res)
        
      caFlag = getCAFlag(res)
            
      caField = None
      if (caFlag == "FALSE"):
        caField = "False"
      if (caFlag == "TRUE"):
        caField = "True"
        
      subjAltName = getSubjAltName(res)

      # get AKID, SKID
      kids = getKIDs(res)
      akid = kids[0]
      skid = kids[1]
            
      sqlString = "UPDATE " + tablename + " \
SET sigAlgo1 = %s, \
version = %s, \
serialno = %s, \
issuer = %s, \
subject = %s, \
notbeforestring = %s, \
notbefore = %s, \
notafterstring = %s, \
notafter = %s, \
keyalgo = %s, \
keylength = %s, \
keymod = %s, \
keyexpo = %s, \
ca = %s, \
subjaltname = %s, \
akid = %s, \
skid = %s \
WHERE hashcert = %s" 

      logSqlString = sqlString
        
      logging.info("")
      logging.info(logSqlString, sigAlgo, version, serialNumber, issuer, subject, 
                   notBeforeString, notBeforeStamp,
                   notAfterString, notAfterStamp,
                   pkAlgorithm, pkLength, pkModulus, pkExponent,
                   caField, subjAltName, akid, skid, hashcert)
      logging.info("")
            
      try:
        c.execute(sqlString, (sigAlgo, version, serialNumber, issuer, subject, 
                              notBeforeString, notBeforeStamp,
                              notAfterString, notAfterStamp,
                              pkAlgorithm, pkLength, pkModulus, pkExponent,
                              caField, subjAltName, akid, skid, hashcert))
      except Exception, e:
        logging.error("ERROR: UPDATE operation failed when sending to cursor.")
        logging.error(e)
        # commit if you have found an error in order to end the current transaction
        # - otherwise all following SQL commands in this transaction will fail, too
        conn.commit()

      sqlCounter = sqlCounter + 1

      # we commit every 10 SQL statements
      if ( (sqlCounter % 10) == 0):
        try:
          conn.commit()
        except Exception, e:
          logging.error("ERROR: UPDATE operation failed when committing.")
          logging.error(e)

      totalCount = totalCount + 1
      logging.info("Current total count (items processed): " + str(totalCount))
      logging.info("######################################################")

    # final commit
    conn.commit()
    print "Done. Total count (items processed) at: " + str(totalCount)
    conn.close()

main()
