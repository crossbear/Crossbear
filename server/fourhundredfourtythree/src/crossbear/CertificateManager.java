/*
    This file is part of Crossbear.

    Crossbear is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Crossbear is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Crossbear.  If not, see <http://www.gnu.org/licenses/>.

    Original authors: Thomas Riedmaier, Ralph Holz (TU Muenchen, Germany)
*/

package crossbear;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Set;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;

import org.bouncycastle.util.encoders.Base64;

import crossbear.messaging.CertVerifyRequest;
import crossbear.messaging.Message;

/**
 * Everything that is connected to processing or storing certificates is done by the CertificateManager.
 * 
 * @author Thomas Riedmaier
 * 
 */
public class CertificateManager {

	/**
	 * Anonymize an IP address by replacing the last block of numbers with a "*".
	 * 
	 * The rationale behind this function is that one the one hand CertificateVerificationRequests should not cause the client's IP to be stored in the database. On the other hand it is desirable to
	 * have as much data at hand as possible when it comes to data evaluation. Not storing the last block of numbers is a compromise. A better one would certainly be to store the client's AS.
	 * This could e.g. be done by executing "whois -h whois.cymru.com \" -v IPADDRESS\" " and parsing the output
	 * 
	 * @param hostAddress
	 *            an IPv4 or IPv6 address that should be Anonymize
	 * @return the hostAddress just that the last block of numbers is replaced with a "*"
	 */
	private static String anonymize(String hostAddress) {
		int lastBlockIndex = Math.max(hostAddress.lastIndexOf(":"), hostAddress.lastIndexOf("."));

		return hostAddress.substring(0, lastBlockIndex + 1) + "*";
	}
	
	/**
	 * Contact a SSL-enabled server and download its certificate chain.
	 * 
	 * Please Note: From version 1.7 on java refuses to connect to SSL-serves using deprecated algorithms like md2 in their certificate chain. Since Crossbear is required to work with these chains
	 * anyways the jdk.certpath.disabledAlgorithms-property should be set to some dummy value like "BLABLABLA". Since calling 'Security.setProperty("jdk.certpath.disabledAlgorithms", "BLABLABLA");'
	 * doesn't work from within a Website this has to be done manualy in the "java.security"-file.
	 * 
	 * @param host The Hostname of the server e.g. "encrypted.google.com"
	 * @param host The ort of the server e.g. 443
	 * @return The certificate chain of that server starting with the server's certificate and continuing with it's chain certificates (if any are sent) along with the IP from which this chain was received
	 * @throws KeyManagementException
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 */
	public static CertificateChainContainer getCertChainFromServer(String host, int port) throws KeyManagementException, IOException, NoSuchAlgorithmException {

		IOException lastCaughtException = null;

		// Attempt twice: Once with TLS/SNI (required for SNI systems and preferred mode for flexible systems)
		// and once with SSL3 using SSLv2Handshake (required for some older systems)
		for (int numberOfTries = 0; numberOfTries < 2; numberOfTries++) {
			try {

				// Force the connection even if the server uses deprecated algorithms
				// since Security.setProperty("jdk.certpath.disabledAlgorithms", "BLABLABLA");
				// is not working when called from jsp it has to be set in the java.security
				// file of the current jvm

				// Force the connection even if the certificate is untrusted
				SSLContext sc = SSLContext.getInstance("SSL");
				sc.init(null, trustAllCerts, new java.security.SecureRandom());
				
				// Create and open a Socket for the connection
				SSLSocket sock;
				if (numberOfTries == 0) {
					
					// Opening the connection has to be done in the createSocket-method or else SNI will not work
					sock = (SSLSocket) sc.getSocketFactory().createSocket(host, port);
				} else {
					
					// In case the the server doesn't support TLS/SSL3 try to use SSLv2Handshake mode
					sock = (SSLSocket) new SSLv2EnabledSocketFactory(sc).createSocket();
					
					// Opening the connection in an extra call allows to specify the timeout value
					sock.connect(new InetSocketAddress(host, port), 3000);
				}				

				// Get the server's IP-Address
				InetAddress serverAddress = ((InetSocketAddress)sock.getRemoteSocketAddress()).getAddress();
				
				// Make sure the handshaking attempt does not take forever
				sock.setSoTimeout(3000);
				
				// Get the certificate chain provided by the server
				Certificate certs[] = sock.getSession().getPeerCertificates();
				
				return new CertificateChainContainer((certs instanceof X509Certificate[]) ? (X509Certificate[]) certs : null, serverAddress);

			} catch (IOException e) {
				lastCaughtException = e;
			}
		}
		// TODO uh, wait a second -- this looks a lot as if we throw an IOException if we cannot connect at all
		// - and that IOException would wander up the whole stack and crash the main
		throw lastCaughtException;

	}

	/**
	 * Take a List of certificates and calculate for each element the MD5-hash of its PEM-representation. Return the concatenation of the hashes.
	 * 
	 * The order of the certificate hashes in the output is Hash(E1)+Hash(E2)+Hash(E3)+...
	 * 
	 * @param certList
	 *            The list of certificates to form the md5 string from
	 * @return The concatenation of the certList's MD5-Hashes in Hex-String representation (e.g. 78A34B9CF....)
	 * @throws CertificateEncodingException
	 * @throws NoSuchAlgorithmException
	 * @throws UnsupportedEncodingException
	 */
	public static String getCertChainMD5(LinkedList<X509Certificate> certList) throws CertificateEncodingException, NoSuchAlgorithmException, UnsupportedEncodingException {
		StringBuilder re = new StringBuilder();

		// Go through all Elements of the chain
		Iterator<X509Certificate> iter = certList.iterator();
		while (iter.hasNext()) {
			// Get the PEM-encoding for each certificate, calculate its MD5-hash and append its HEX-String representation to the output
		    String hulla = getPemEncoding(iter.next());
		    System.out.println("PEM encoding: " + hulla);
		    String m = Message.byteArrayToHexString(MD5(hulla.getBytes("UTF-8")));
		    System.out.println("My hash is: " + m);
			re.append(m);
		}

		return re.toString();
	}
	
	/**
	 * Get all IDs of certificates with a certain SHA256DERHash
	 * 
	 * @param certHash The hash that the certificates need to share
	 * @param db The database connection to use
	 * @return A comma-separated list of the IDs of the certificates that share "certHash" as SHA256DERHash
	 * @throws InvalidParameterException
	 * @throws SQLException
	 */
	public static String getCertIDs(byte[] certHash, Database db) throws InvalidParameterException, SQLException{
		
		// Query the database for the list
		Object[] params = { Message.byteArrayToHexString(certHash) };
		ResultSet rs = db.executeQuery("SELECT array_to_string(array_agg(DISTINCT Id),', ') AS IDs FROM ServerCerts WHERE SHA256DERHash = ?", params);

		// If the result is empty then there is no certificate that has that hash -> return an empty String
		if (!rs.next()) {
			return "";
		}
		
		// Return the list
		return rs.getString("IDs");
	}


	/**
	 * Java comes with a list of trusted CAs stored in a keystore file. This function loads that keystore from disc and returns it.
	 * 
	 * The code was created by the use of http://www.exampledepot.com/egs/java.security.cert/ValidCertPath.html
	 * 
	 * @param password The password for accessing the local CA Keystore
	 * @return The system's Trusted-CAs keystore
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 * @throws KeyStoreException
	 */
	private static KeyStore getLocalCAKeystore(String password) throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {

		// The trusted-CAs' keystore is located inside the JAVA-Home directory - get it's path
		/* 
		 * TODO: swap Java Root Store for Mozilla Root Store that is up-to-date (as it is done in the current installation)
		 */
		String filename = System.getProperty("java.home") + "/lib/security/cacerts".replace('/', File.separatorChar);

		// Open and load it using the default password
		FileInputStream is = new FileInputStream(filename);
		KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		keystore.load(is, password.toCharArray());

		return keystore;

	}

	/**
	 * Get the PEM-representation of a certificate.
	 * 
	 * Please note: The PEM encoding returned by this function is structured in lines of 64 characters each. Linebreaks are equal to a \n
	 * 
	 * @param cert
	 *            The certificate
	 * @return The PEM representation of cert
	 * @throws CertificateEncodingException
	 */
	private static String getPemEncoding(X509Certificate cert) throws CertificateEncodingException {

		// Get the bytes of the certificate and encode them in base64
		String base64EncodedCert = new String(Base64.encode(cert.getEncoded()));

		// Write the PEM header
		String re = "-----BEGIN CERTIFICATE-----\n";

		// Write the certificate data in lines of 64 chars
		int len = base64EncodedCert.length();
		for (int i = 0; i < len; i += 64) {
			re += base64EncodedCert.substring(i, Math.min(len, i + 64)) + "\n";
		}

		// Write the PEM trailer
		re += "-----END CERTIFICATE-----";

		// Return the PEM-representation of the certificate
		return re;
	}
	
	/**
	 * Try to retrieve a server's certificate from the local cache i.e. the CertCache-table
	 * 
	 * @param hostPort
	 *            The Hostname and port of the server e.g. encrypted.google.com:443
	 * @param db
	 *            The database connection to use
	 * @return The server's certificate if a cache entry exists that is currently valid else null .
	 * @throws CertificateException
	 * @throws SQLException
	 */
	private static X509Certificate getServerCertFromCache(String hostPort, Database db) throws CertificateException, SQLException {

		Object[] params = { hostPort };
		ResultSet rs = db.executeQuery("SELECT * FROM CertCache WHERE HostPort = ? LIMIT 1", params);

		// If the result is empty then there is no cache entry to return
		if (!rs.next()) {
			return null;
		}

		// If the cache entry is not valid anymore then there is nothing to return
		Timestamp validUntil = rs.getTimestamp("ValidUntil");
		if (validUntil.before(new Timestamp(System.currentTimeMillis())))
			return null;

		// If there is a cache entry that is currently valid: return its certificate.
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		return (X509Certificate) cf.generateCertificate(rs.getBinaryStream("Certificate"));

	}

	/**
	 * Checks whether a given X.509 certificate is self-signed.
	 * 
	 * The code was created by the use of http://www.nakov.com/blog/2009/12/01/x509-certificate-validation-in-java-build-and-verify-chain-and-verify-clr-with-bouncy-castle/
	 * 
	 * @param cert
	 *            The certificate to check
	 * @return True if the certificate is self signed and false if not
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 */
	private static boolean isSelfSigned(X509Certificate cert) throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException {
		try {
			// Try to verify certificate signature with its own public key
			PublicKey key = cert.getPublicKey();
			cert.verify(key);
			return true;
		} catch (SignatureException sigEx) {
			// Invalid signature --> not self-signed
			return false;
		} catch (InvalidKeyException keyEx) {
			// Invalid key --> not self-signed
			return false;
		}
	}
	
	/**
	 * Read a certificate from a file. The certificate can be either binary or base64 encoded.
	 * 
	 * This function was created by the use of http://www.exampledepot.com/egs/java.security.cert/ImportCert.html
	 * 
	 * @param fileName The path and name of the file to read (e.g. ../server.crt)
	 * @return The certificate that was read from the file with name "fileName"
	 * @throws FileNotFoundException
	 * @throws CertificateException
	 */
	public static X509Certificate loadCertificateFromFile(String fileName) throws FileNotFoundException, CertificateException {

		// Try to open the file
		FileInputStream is = new FileInputStream(fileName);

		// Parse the file's content as certificate
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		Certificate cert = cf.generateCertificate(is);
		
		// Cast the certificate into a X509Certificate and return it
		return (X509Certificate) cert;

	}

	/**
	 * Hash a byte[] using the MD5-algorithm
	 * 
	 * @param data
	 *            The byte[] to hash
	 * @return The MD5 hash of data represented by a byte[] of length 16
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] MD5(byte[] data) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("MD5");
		return md.digest(data);
	}
	
	/**
	 * Store the observation of a certificate in the CertObservations-table
	 * 
	 * @param certID
	 *            The ID of the certificate (i.e. the Id column of the ServerCerts-table)
	 * @param serverHostPort
	 *            The Hostname and port of the server for which the certificate has been observed (e.g. encrypted.google.com:443)
	 * @param serverIP
	 *            The IP of the server for which the certificate has been observed
	 * @param serverTimeOfExecution
	 *            The time of the observation (always the server's time - never the client's local time)
	 * @param observerType
	 *            An Identifier for the observer's type (e.g. "CrossbearServer" or "CrossbearCVR")
	 * @param observerIP
	 *            The IP from which the observation was made (might be partially anonymized)
	 * @param db
	 *            The database connection to use
	 * @return The value of the Id-column of the newly created entry in the CertObservations-table
	 * @throws NumberFormatException 
	 * @throws InvalidParameterException
	 * @throws SQLException
	 */
	public static long rememberCertObservation(Long certID, String serverHostPort, String serverIP, Timestamp serverTimeOfExecution, String observerType, String observerIP, Database db) throws NumberFormatException, InvalidParameterException, SQLException  {

		// Create an entry of the observation in the CertObservations table
		Object[] params = { certID, serverHostPort, serverIP, serverTimeOfExecution, observerType, observerIP };
		return Long.valueOf(db.executeInsert("INSERT INTO CertObservations ( CertID, ServerHostPort, ServerIP, TimeOfObservation, ObserverType, ObserverIP) VALUES (?,?,?,?,?,?)", params));

	}
	
	
	/**
	 * Hash a byte[] using the SHA1-algorithm
	 * 
	 * @param data
	 *            The byte[] to hash
	 * @return The SHA1 hash of data represented by a byte[] of length 20
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] SHA1(byte[] data) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		return md.digest(data);
	}

	/**
	 * Hash a byte[] using the SHA256-algorithm
	 * 
	 * @param data
	 *            The byte[] to hash
	 * @return The SHA256 hash of data represented by a byte[] of length 32
	 * @throws NoSuchAlgorithmException
	 */
	public static byte[] SHA256(byte[] data) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		return md.digest(data);
	}
	
	/**
	 * Store a certificate in the database. Depending on whether the certificate is actually a server's certificate or only a chain certificate is is either stored in the ServerCerts-table or in the
	 * ChainCerts-table. In case the certificate already exists the database entry is not modified.
	 * 
	 * @param cert
	 *            The certificate to store
	 * @param isChainCert
	 *            Is the certificate to store a chain certificate?
	 * @param certChainMd5
	 * 			  The md5-hash of the certificate chain in case the certificate is a server certificate. If it should not be set, then this parameter should be "null"
	 * @param db
	 *            The database connection to use
	 * @return The ID of the certificate after it has been inserted either into the ChainCerts or into the ServerCerts table. If it was already inserted, the old ID is returned
	 * @throws SQLException
	 * @throws CertificateEncodingException
	 * @throws NoSuchAlgorithmException
	 * @throws UnsupportedEncodingException
	 */
	private static Long storeCert(X509Certificate cert, boolean isChainCert, String certChainMd5, Database db) throws SQLException, CertificateEncodingException, NoSuchAlgorithmException, UnsupportedEncodingException {

		Long re;
		SQLException lastSQLException = null;

		// Calculate the certificate's SHA256-Hash
		String certSHA256 = Message.byteArrayToHexString(SHA256(cert.getEncoded()));

		/*
		 * "Insert-if-not-exists" requires two SQL statements. Since the state of the database might change in between the two statements transactions are used. Transactions might fail on commit. The
		 * only legal reason for that is that the entry that should be inserted has already been inserted in the meantime. In that case try getting that entry and if that succeeded go on. If that
		 * failed again then there is a real problem and an exception is thrown.
		 */
		db.setAutoCommit(false);
		for (int i = 0; i < 2; i++) {
			try {

				// First: Check if the entry already exists.
				ResultSet rs;
				if(isChainCert){
					Object[] params =  { certSHA256 };
					rs = db.executeQuery("SELECT Id FROM ChainCerts WHERE SHA256DERHash = ? LIMIT 1", params);
				} else {
					if(certChainMd5 == null){
						Object[] params =  { certSHA256};
						rs = db.executeQuery("SELECT Id FROM ServerCerts WHERE SHA256DERHash = ? AND CertChainMD5 IS NULL LIMIT 1", params);
					} else {
						Object[] params =  { certSHA256 , certChainMd5};
						rs = db.executeQuery("SELECT Id FROM ServerCerts WHERE SHA256DERHash = ? AND CertChainMD5 = ? LIMIT 1", params);	
					}
				}


				// If not add a new entry to the database
				if (!rs.next()) {

					String certPem = getPemEncoding(cert);
					String certSHA1 = Message.byteArrayToHexString(SHA1(cert.getEncoded()));
					String certPemMd5 = Message.byteArrayToHexString(MD5(certPem.getBytes("UTF-8")));
					
					String key;
					if(isChainCert){
						Object[] params2 = { certSHA256,certSHA1, cert.getEncoded(), certPemMd5, certPem };
						key = db.executeInsert("INSERT INTO ChainCerts (SHA256DERHash,SHA1DERHash, DERRaw, MD5PEMHash, PEMRaw) VALUES (?,?,?,?,?)", params2);
					} else {
						if(certChainMd5 == null){
							Object[] params2 = { certSHA256, certSHA1, cert.getEncoded(), certPemMd5, certPem };
							key = db.executeInsert("INSERT INTO ServerCerts (SHA256DERHash,SHA1DERHash, DERRaw, MD5PEMHash, PEMRaw) VALUES (?,?,?,?,?)", params2);
						} else {
							
							String certChainSHA256 = Message.byteArrayToHexString(SHA256(Message.hexStringToByteArray(certSHA256+certChainMd5)));
									
							Object[] params2 = { certSHA256, certSHA1, cert.getEncoded(), certPemMd5, certPem, certChainMd5,certChainSHA256 };
							key = db.executeInsert("INSERT INTO ServerCerts (SHA256DERHash,SHA1DERHash, DERRaw, MD5PEMHash, PEMRaw, CertChainMD5, SHA256ChainHash) VALUES (?,?,?,?,?,?,?)", params2);
						}
					}

					// The call to this function actually inserted a entry in the database
					re = Long.valueOf(key);

				} else {

					// The call to this function did not insert a entry in the database
					re = Long.valueOf(rs.getString("Id"));
				}

				// Try to commit the changes
				db.commit();

				// Reenable auto-commit
				db.setAutoCommit(true);
				return re;
			} catch (SQLException e) {

				// Commit failed. If that was the first time: Try again
				db.rollback();
				lastSQLException = e;
			}
		}
		throw lastSQLException;
	}
	
	/**
	 * Store the result of a Hunting Task in the HuntingTaskResults-table
	 * 
	 * @param taskID
	 *            The ID of the Hunting Task
	 * @param trace
	 *            The trace that was observed
	 * @param observID
	 *            The ID of the certificate observation that was made
	 * @param db
	 *            The database connection to use
	 * @throws InvalidParameterException
	 * @throws SQLException
	 */
	public static void storeHuntingTaskResult(int taskID, String trace, Long observID, Database db) throws InvalidParameterException, SQLException {

		Object[] params = { taskID, trace, observID };
		db.executeInsert("INSERT INTO HuntingTaskResults ( HuntingTaskID, Trace, Observation) VALUES (?,?,?)", params);

	}
	
	/**
	 * Store a server's certificate in the local certificate cache (i.e. the CertCache-table). The local certificate cache is used to reduce the network traffic generated by Crossbear and to speed up
	 * the average response time of Certificate Verification Requests.
	 * 
	 * @param cert
	 *            The certificate to store
	 * @param hostPort
	 *            The Hostname and port of the server for which the certificate should be stored (e.g. encrypted.google.com:443)
	 * @param validity
	 *            The time in milliseconds that the entry should stay valid.
	 * @param db
	 *            The database connection to use
	 * @throws SQLException
	 * @throws CertificateEncodingException
	 */
	private static void storeServerCertInCache(X509Certificate cert, String hostPort, long validity, Database db) throws SQLException, CertificateEncodingException {

		SQLException lastSQLException = null;

		/*
		 * "Update-or-Insert" requires two SQL statements. Since the state of the database might change in between the two statements transactions are used. Transactions might fail on commit. The only
		 * legal reason for that is that the entry that should be inserted has already been inserted in the meantime. In that case try updating that entry and if that succeeded go on. If that failed
		 * again then there is a real problem and an exception is thrown.
		 */
		db.setAutoCommit(false);
		for (int i = 0; i < 2; i++) {
			try {

				// First: Try to update an existing entry
				Object[] params = { cert.getEncoded(), new Timestamp(System.currentTimeMillis() + validity), hostPort };
				int updatedRows = db.executeUpdate("UPDATE CertCache SET Certificate = ?, ValidUntil = ? WHERE HostPort = ?", params);

				// If there isn't any try to insert a new one.
				if (updatedRows == 0) {
					db.executeInsert("INSERT INTO CertCache (Certificate,ValidUntil,HostPort) VALUES (?,?,?)", params);
				}

				// Try to commit the changes
				db.commit();

				// Reenable auto-commit
				db.setAutoCommit(true);
				return;
			} catch (SQLException e) {

				// Commit failed. If that was the first time: Try again
				db.rollback();
				lastSQLException = e;
			}
		}
		throw lastSQLException;

	}

	// The KeyStore containing the root-CA certificates trusted by the local system
	private final KeyStore localCAKeystore;

	// A Trust manager that does not validate certificate chains
	// (required in order to be able to download certificates whose root certificates are not known)
	private static final TrustManager[] trustAllCerts = new TrustManager[] { new TrustAllCertificatesTM()};

	// The duration in seconds a entry will be valid in a cache. This value is used when writing into a cache not when reading from it
	private int cacheValidity;

	/**
	 * Create a new CertificateManager with a database backend.
	 * 
	 * During the creation the local system's trusted root-CA KeyStore will be read and stored in the ChainCerts-table and the localCAKeystore variable. The localCAKeystore is needed because some
	 * websites don't send complete certificate chains since they assume that the clients know their root certificate. Crossbear tries to store the certificate chain for each certificate it observes.
	 * However, this is only done when the chain could be validated and that might require the local system's root-CA KeyStore.
	 * 
	 * @param db
	 *            The database connection that will be used to insert the local system's root-CAs into the ChainCerts-table.
	 * @param cacheValidity
	 *            The duration in seconds a entry will be valid in a cache. This value is used when writing into a cache not when reading from it.
	 * @param password The password for accessing the local CA Keystore
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 * @throws SQLException
	 * @throws CertificateException
	 * @throws IOException
	 */
    public CertificateManager(Database db, int cacheValidity, String password) throws NoSuchAlgorithmException, KeyStoreException, SQLException, CertificateException, IOException {

		// Remember the cacheValidity
		this.cacheValidity = cacheValidity;

		// Load the local system's root-CA KeyStore and store it in the ChainCerts-table
		this.localCAKeystore = getLocalCAKeystore(password);
		addCAsFromLocalCAKeyStoreToDB(db);
	}

	/**
	 * Create a new CertificateManager without a database backend.
	 * 
	 * During the creation the local system's trusted root-CA KeyStore will be read and stored in the ChainCerts-table and the localCAKeystore variable. The localCAKeystore is needed because some
	 * websites don't send complete certificate chains since they assume that the clients know their root certificate. Crossbear tries to store the certificate chain for each certificate it observes.
	 * However, this is only done when the chain could be validated and that might require the local system's root-CA KeyStore.
	 * 
	 * @param cacheValidity
	 *            The duration in seconds a entry will be valid in a cache. This value is used when writing into a cache not when reading from it.
	 * @param password The password for accessing the local CA Keystore
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 * @throws SQLException
	 * @throws CertificateException
	 * @throws IOException
	 */
	public CertificateManager(int cacheValidity, String password) throws NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {

		// Remember the cacheValidity
		this.cacheValidity = cacheValidity;

		// Load the local system's root-CA KeyStore and store it in the ChainCerts-table
		this.localCAKeystore = getLocalCAKeystore(password);
	}

	/**
	 * Insert all certificates from the localCAKeystore KeyStore into the ChainCerts-table
	 * 
	 * @param db
	 *            The database-connection to use
	 * @throws CertificateEncodingException
	 * @throws NoSuchAlgorithmException
	 * @throws UnsupportedEncodingException
	 * @throws SQLException
	 * @throws KeyStoreException
	 */
	private void addCAsFromLocalCAKeyStoreToDB(Database db) throws CertificateEncodingException, NoSuchAlgorithmException, UnsupportedEncodingException, SQLException, KeyStoreException {

		// Get the names of all keys contained in the localCAKeystore KeyStore
		Enumeration<String> allKeyAliases = localCAKeystore.aliases();

		// For each key: Get the corresponding certificate and insert it in the ChainCerts-table
		while (allKeyAliases.hasMoreElements()) {

			// get it
			Certificate cert = localCAKeystore.getCertificate(allKeyAliases.nextElement());

			// store it in the ChainCerts-table
			if (cert instanceof X509Certificate) {
				storeCert((X509Certificate) cert, true,null, db);
			}
		}

	}

	/**
	 * This function checks if the certificate for a server is already known (i.e. if it is in cache). If that is the case it is returned. If not the server itself is contacted and its certificate is
	 * downloaded. The event of that certificate observation is then stored in the database as is the certificate's chain. Finally the certificate is inserted into the cache (i.e. the CertCache-table)
	 * and returned.
	 * 
	 * @param cvr
	 *            The CertVerifyRequest containing the Host's name and port
	 * @param db
	 *            The database connection to use
	 * @return The Host's certificate or null if it could not be obtained
	 * @throws InvalidParameterException
	 * @throws NoSuchAlgorithmException
	 * @throws SQLException
	 * @throws InvalidAlgorithmParameterException
	 * @throws KeyStoreException
	 * @throws CertificateException
	 * @throws KeyManagementException
	 * @throws IOException
	 * @throws NoSuchProviderException
	 */
	public X509Certificate getCertForHost(CertVerifyRequest cvr, Database db) throws InvalidParameterException, NoSuchAlgorithmException, SQLException, InvalidAlgorithmParameterException,
			KeyStoreException, CertificateException, KeyManagementException, IOException, NoSuchProviderException {

		// Concatenate hostname and hostport to hostport. Hostport is the host's identifier in the database
		String serverHostPort = cvr.getHostName() + ":" + String.valueOf(cvr.isUserUsingProxy()?443:cvr.getHostPort());

		// first try to load the certificate from the local cache
		X509Certificate serverCert = getServerCertFromCache(serverHostPort, db);
		if (null != serverCert)
			return serverCert;

		// if that failed try to load it from the server (port depends on whether the cvr was generated by a user that uses a SSL-Proxy)
		X509Certificate[] serverCertChain = null;
		CertificateChainContainer CCC = null;
		try {
			CCC = getCertChainFromServer(cvr.getHostName(), cvr.isUserUsingProxy() ? 443 : cvr.getHostPort());
			serverCertChain = CCC.getChain();
		} catch (IOException e) {

			// ... and if that was not possible: set it to null
			serverCertChain = null;
		}
		if (null == serverCertChain)
			return null;

		// if that worked store it in the local cache ...
		storeServerCertInCache(serverCertChain[0], serverHostPort, cacheValidity, db);

		// ... then store the whole chain (if not already stored) ...
		Long serverCertID = storeCertChain(serverCertChain, db);

		// ... and remember the observation of the server's cert in the CertObservations table.
		rememberCertObservation(serverCertID, serverHostPort, CCC.getServerAddress().getHostAddress(), new Timestamp(System.currentTimeMillis()), "CrossbearServer", cvr
				.getLocalAddr().getHostAddress(), db);

		// Finally return the server's cert
		return serverCertChain[0];
	}

	/**
	 * This function extracts the certificate that the client observed from the CertVerifyRequest and stores it in the database. Then the event of the certificate observation is also stored in the
	 * database. Finally the observed certificate is returned.
	 * 
	 * @param cvr
	 *            The CertVerifyRequest containing the server's certificate observed by the client
	 * @param db
	 *            The database connection to use
	 * @return The observed certificate
	 * @throws InvalidParameterException
	 * @throws NoSuchAlgorithmException
	 * @throws SQLException
	 * @throws UnsupportedEncodingException
	 * @throws NoSuchProviderException 
	 * @throws CertificateException 
	 * @throws KeyStoreException 
	 * @throws InvalidAlgorithmParameterException 
	 */
	public X509Certificate getCertFromRequest(CertVerifyRequest cvr, Database db) throws InvalidParameterException, NoSuchAlgorithmException, SQLException,
			UnsupportedEncodingException, InvalidAlgorithmParameterException, KeyStoreException, CertificateException, NoSuchProviderException {

		// Concatenate hostname and hostport to hostport. Hostport is the host's identifier in the database
		String serverHostPort = cvr.getHostName() + ":" + String.valueOf(cvr.isUserUsingProxy()?443:cvr.getHostPort());

		// Extract the server's certificate chain from the request ...
		X509Certificate[] requestCertChain = cvr.getCertChain();

		// ... store it in the database (if not already done before) ...
		Long requestCertID = storeCertChain(requestCertChain, db);

		// ... and remember it's observation in the CertObservations table
		rememberCertObservation(requestCertID, serverHostPort, cvr.getHostIP().getHostAddress(), new Timestamp(System.currentTimeMillis()), "CrossbearCVR",
				cvr.isUserUsingProxy()?cvr.getRemoteAddr().getHostAddress():anonymize(cvr.getRemoteAddr().getHostAddress()), db);

		// Finally: return it
		return requestCertChain[0];
	}
	

	/**
	 * Take a certificate chain and see if there is a way in which
	 * it can be ordered that makes it valid. This is necessary
	 * since there is no guarantee, that certificate chains are
	 * transmitted in correct order.
	 * 
	 * If the chain's end is required to be self-signed and the
	 * root-of-trust is not within the chain, there will be an
	 * attempt to find it in the system's root-CA KeyStore.
	 * 
	 * @todo: the system's root CA store might be different depending on the JVM - we should replace it with a list of our own
	 * @todo: remove the limit of maxPermutations - it is not necessary
	 * 
	 * @param in The certificate chain to check
	 * @param maxPermutations The maximal number of reordering-attempts to make (first attempt will always be the original order)
	 * @param endMustBeSelfSigned States if the chain's end must be self signed.
	 * @return The reordered version of "in" that has been enhanced by the chain's root-of-trust if that was necessary in order to make the end self signed. If there was no ordering found to make the chain valid then null is returned.
	 * @throws InvalidAlgorithmParameterException
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws NoSuchProviderException
	 */
	public LinkedList<X509Certificate> makeCertChainValid(X509Certificate[] in, int maxPermutations, boolean endMustBeSelfSigned) throws InvalidAlgorithmParameterException, KeyStoreException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException {
		
		// Create a Permutation generator of suitable length
		PermutationGenerator permGen = new PermutationGenerator(in.length - 1);
		
		// Set a limit of how many permutations are tried maximally and start trying them (first attempt will be the original order)
		while (permGen.hasMore() && maxPermutations-- > 0) {

			// Create a new cerificate permutation and set its first element to the host's certificate
			LinkedList<X509Certificate> certPerm = new LinkedList<X509Certificate>();
			certPerm.add(in[0]);

			// Set the remaining chain according to the current permutation (starting with the original order)
			int[] permutation = permGen.getNext();
			for (int i = 0; i < permutation.length; i++) {
				certPerm.add(in[permutation[i] + 1]);
			}

			// See if this permutation is valid (and if applicable: is its end self-signed )
			LinkedList<X509Certificate> validatedList = validateCertChain(certPerm, endMustBeSelfSigned);

			// If it is: return it
			if (null != validatedList) {
				return validatedList;

			}

		}
		
		// If no way was found to make the chain valid: return null
		return null;
	}

	/**
	 * This function takes a certificate chain and stores its first element in the ServerCerts-table and the remainder in the ChainCerts-table.
	 * 
	 * In case the last element of the certificate chain is self-signed and the certificate chain is valid, the getCertChainMD5 is called and the result is stored along with the server certificate.
	 * The same is done in case the last element of the chain is not self signed but an entry in the localCAKeystore-KeyStore exists that completes the chain. If the
	 * chain is either invalid or could not be completed the certificate chain is not set. In that case the CertChainMD5 is just left "null".
	 * 
	 * @param certs
	 *            The certificate chain to store (certs[0] is assumed to be the server's certificate)
	 * @param db
	 *            The database connection to use
	 * @return The ID of the server's certificate after it has been inserted into the ServerCerts table. If it was already inserted, the old ID is returned
	 * @throws InvalidAlgorithmParameterException
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws SQLException
	 * @throws UnsupportedEncodingException
	 * @throws NoSuchProviderException
	 */
	public Long storeCertChain(X509Certificate[] certs, Database db) throws InvalidAlgorithmParameterException, KeyStoreException, NoSuchAlgorithmException, CertificateException, SQLException,
			UnsupportedEncodingException, NoSuchProviderException {

		// See if there is a way in which the certificate chain can be ordered so that it is valid and its end is self-signed. If necessary add a chain terminator from the system's root-CA KeyStore to
		// do so.
		LinkedList<X509Certificate> validatedChain = makeCertChainValid(certs, 50, true);

		String certChainMD5 = null;
		
		// If the chain is valid: Calculate it's md5-hash
		if (validatedChain != null) {

			// Remove the server's certificate from the chain
			validatedChain.removeFirst();

			// Get the concatenation of the md5 hashes of the chain's certificates ...
			certChainMD5 = getCertChainMD5(validatedChain);
		}

		// Insert all elements of the certificate chain
		for (int i = 1; i < certs.length; i++) {
			storeCert(certs[i], true, null, db);
		}
		
		// Insert the server's certificate and return it's ID
		return storeCert(certs[0], false, certChainMD5, db);

	}

	/**
	 * This function validates a certificate-chain (i.e. checks if if each certificate in the chain is signed by the following one.).
	 * 
	 * If the certificate-chain's end must be self signed but is not, the localCAKeystore is searched for a chain terminator.
	 * 
	 * The code was created by the use of http://www.nakov.com/blog/2009/12/01/x509-certificate-validation-in-java-build-and-verify-chain-and-verify-clr-with-bouncy-castle/
	 * 
	 * @param certChain
	 *            The certificate chain to validate
	 * @param endMustBeSelfSigned States if the chain's end must be self signed.
	 * @return Null if the validity of the certificate chain could not be confirmed. If it could be confirmed "in" that was enhanced by its root-of-trust if that has not already been the chain's end.
	 * @throws InvalidAlgorithmParameterException
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws NoSuchProviderException 
	 */
	private LinkedList<X509Certificate> validateCertChain(LinkedList<X509Certificate> in, boolean endMustBeSelfSigned) throws InvalidAlgorithmParameterException, KeyStoreException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException {
		
		// Make a copy of "in"
		LinkedList<X509Certificate> certChain = new LinkedList<X509Certificate>(in);
		Collections.copy(certChain,in);

		/*
		 * The chain's terminator might be inside the system's root-CA KeyStore. If a chain is only valid if it is terminated (i.e. endMustBeSelfSigned==true ) and it is not yet terminated, the
		 * system's root-CA KeyStore is used as Set of possible trust anchors. If that is not true the last element of the certificate chain is used as only possible trust anchor.
		 */
		PKIXParameters params;
		if (endMustBeSelfSigned && !isSelfSigned(certChain.getLast())) {
			// Use all of the CAs from the local system's root-CA KeyStore as possible trust anchors
			params = new PKIXParameters(localCAKeystore);
		} else {
			// Use the end of the certificate chain as trust anchor (may or may not be self-signed). Since it is then no longer a member of the chain -> remove it
			Set<TrustAnchor> trustedAnchors = new HashSet<TrustAnchor>();
			trustedAnchors.add(new TrustAnchor(certChain.removeLast(), null));

			params = new PKIXParameters(trustedAnchors);
		}

		// Disable CRL checking since we are not supplying any CRLs
		params.setRevocationEnabled(false);

		// Disable "valid today" check (chain should be stored if it is valid within itself - no matter whether it is valid now)
		params.setDate(in.getFirst().getNotAfter());

		// Cast the certificate List into a CertPath
		CertificateFactory certFact = CertificateFactory.getInstance("X.509");
		CertPath certPath = certFact.generateCertPath(certChain);

		// Use a CertPathValidator on the CertPath
		CertPathValidator certPathValidator = CertPathValidator.getInstance(CertPathValidator.getDefaultType());

		// Check if the chain is valid and if it ends at (one of) the chosen trust anchor(s)
		try {
			// Assuming the chain is valid: Get its TrustAnchor (will throw an exception if it is not valid)
			TrustAnchor ta = ((PKIXCertPathValidatorResult)certPathValidator.validate(certPath, params)).getTrustAnchor();
			
			// Add the trust anchor to the end of the chain (if it was there originally it was removed some lines above so it needs to be added again)
			certChain.add(ta.getTrustedCert());
			
			// And return it
			return certChain;
		} catch (CertPathValidatorException e) {
			
			// Validation was not possible: return null
			return null;
		}

	}

}
