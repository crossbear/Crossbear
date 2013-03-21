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
*/

package crossbear;

import java.io.IOException;
import java.net.InetAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.sql.Date;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;

import crossbear.convergence.ConvergenceConnector;
import crossbear.messaging.CertVerifyRequest;
import crossbear.messaging.CertVerifyResult;
import crossbear.messaging.CurrentServerTime;
import crossbear.messaging.HuntingTask;
import crossbear.messaging.Message;
import crossbear.messaging.MessageList;
import crossbear.messaging.PublicIPNotification;
import crossbear.messaging.MessageSerializationException;

/**
 * The CVRProcessor takes as input a CertVerifyRequest and judges its certificate based on various criteria. It returns a MessageList consisting of a CertVerifyResult and optionally a
 * CurrentServerTime-message a PublicIPNotification-message and a HuntingTask-message if the CertVerifyResult is worth creating a hunting task.
 * 
 * The CVRProcessor also provides a cache-functionality for CertVerifyResults.
 * 
 * Some domains that could be used for testing:
 * 
 * https://docs.indymedia.org/ (self signed) 
 * https://publish.indymedia.org/ (self signed, not valid today) 
 * https://saanet.sg/ (not valid today, two elements in chain)
 * https://sso.cs.ohm-hochschule.de (private signing authority)
 * https://alice.sni.velox.ch and https://bob.sni.velox.ch (SNI)
 * https://banking.dkb.de (MD2 in CERT chain)
 * https://lipari.net.in.tum.de (wrong certificate)
 * https://www.cacert.org (ca cert)
 * https://citi.bridgetrack.com (unordered certificate chain)
 * 
 * They can be inserted as Hunting-Task targets by executing 
 * INSERT INTO Huntingtasks (TargetHostName, TargetIP, TargetPort , TimeOfCreation , Active) VALUES
 * ('docs.indymedia.org', '209.234.249.215', '443', NOW(), 'true'),
 * ('publish.indymedia.org', '204.13.164.127', '443', NOW(), 'true'),
 * ('saanet.sg', '94.127.69.161', '443', NOW(), 'true'),
 * ('sso.cs.ohm-hochschule.de', '141.75.237.80', '443', NOW(), 'true'),
 * ('alice.sni.velox.ch', '62.75.148.60', '443', NOW(), 'true'),
 * ('bob.sni.velox.ch', '62.75.148.60', '443', NOW(), 'true'),
 * ('banking.dkb.de', '212.34.73.132', '443', NOW(), 'true'),
 * ('lipari.net.in.tum.de', '131.159.14.104', '443', NOW(), 'true'),
 * ('www.cacert.org', '213.154.225.245', '443', NOW(), 'true'),
 * ('citi.bridgetrack.com', '216.250.63.5', '443', NOW(), 'true');
 * 
 * @author Thomas Riedmaier
 * 
 */
public class CVRProcessor {

	// Regex to match the commonName-part within a Distinguished Name
	private static final Pattern cnPat = Pattern.compile("CN=[a-zA-Z0-9\\.\\-\\*]*", Pattern.CASE_INSENSITIVE);
	
	// Regex that will match the deprecated algorithms MD2, MD5 (and all others of the MD-family)
	private static final Pattern deprecatedAlgPat = Pattern.compile("md\\d", Pattern.CASE_INSENSITIVE);

	/**
	 * Judge the equality of two certificates. There are three possible outcomes: 
	 * - No certificate could be obtained from the server by the Crossbear server
	 * - Both certificates are equal
	 * - The certificates are not equal
	 * 
	 * @param serverCert The certificate of the server observed by the Crossbear server
	 * @param requestCert The certificate of the server observed by a Crossbear client
	 * @return A CertJudgment reflecting the equality of the two certificates
	 * @throws CertificateEncodingException
	 */
	private static CertJudgment getJudgmentOfCertEquality(X509Certificate serverCert, X509Certificate requestCert) throws CertificateEncodingException {

		if (serverCert == null) {
			return new CertJudgment("<crit>CERTCOMPARE: NO CERT RECEIVED</crit>", -100);
			
		} else if (Arrays.equals(serverCert.getEncoded(), requestCert.getEncoded())) {
			return new CertJudgment("CERTCOMPARE: same", 80);
			
		} else {
			return new CertJudgment("<crit>CERTCOMPARE: DIFFERENT</crit>", 0);

		}

	}
	
	/**
	 * Judge if a certificate is currently valid. There are two possible outcomes:
	 * - Valid now
	 * - Not Valid Now
	 * 
	 * @param cert The certificate to judge
	 * @return A CertJudgment reflecting the current validity of the certificate
	 */
	private static CertJudgment getJudgmentOfCurrentValidity(X509Certificate cert){
		
		try {
			cert.checkValidity();
			return new CertJudgment("VALIDITY: now", 20);
		} catch (Exception e) {
			return new CertJudgment("<crit>VALIDITY: NOT NOW</crit>", -20);
		}
		
	}

	/**
	 * Judge if a certificate is valid for a host. This is done by deep certificate inspection and not by calling high level functions since they might be vulnerable to attacks like the Null Prefix
	 * Attack (http://www.thoughtcrime.org/papers/null-prefix-attacks.pdf). There are four possible outcomes:
	 * - The CN could not be found inside the certificate
	 * - The CN is invalid (most likely because of an attack)
	 * - The CN is valid but doesn't match the host
	 * - The CN is valid and matches the host
	 * 
	 * @param cert The certificate to judge
	 * @param host The host for wich it claims to be valid
	 * @return A CertJudgment stating if a certificate is valid vor a host.
	 * @throws CertificateEncodingException
	 * @throws CertificateParsingException
	 */
	private static CertJudgment getJudgmentOfDomainMatch(X509Certificate cert, String host) throws CertificateEncodingException, CertificateParsingException {

		// Search the certificate for all of it's Common Names
		boolean couldExtractCN = false;
		Vector<byte[]> cnBytes = new Vector<byte[]>();
		try {
			// Cast the certificate into a DERSequence ... 
			DERSequence seq = (DERSequence) DERSequence.fromByteArray(cert.getEncoded());

			// ... and search it for Common Names
			searchSequenceForCNs(seq, cnBytes);

			// If any were found remember that
			if (cnBytes.size() > 0)
				couldExtractCN = true;

		} catch (IOException e) {
		} finally {
			// If no Common Names were found report that
			if (!couldExtractCN) {
				return new CertJudgment("<crit>CERT->DOMAIN: CN NOT FOUND</crit>", 0);
			}
		}

		// Assert that none of the found CNs is malicious
		boolean allCNsAreValid = true;
		for (int i = 0; i < cnBytes.size(); i++) {
			allCNsAreValid &= isValidCN(cnBytes.get(i));
		}

		// If any of the CNs is malicious report that
		if (!allCNsAreValid) {
			return new CertJudgment("<crit>CERT->DOMAIN: CN IS INVALID</crit>", -200);
		}

		// Get all domains for which the certificate is valid
		Vector<String> domains = new Vector<String>();
		
		// First: Extract the main DN-field from the certificate
		domains.add(getURLFromDN(cert.getSubjectDN().getName()));
		
		// Second: Extract all alternative names from the certificate
		Collection<List<?>> sans = cert.getSubjectAlternativeNames();
		if (null != sans) {
			for (List<?> next : sans) {
				Object entry = next.get(1);
				if(entry instanceof String){
					domains.add((String) entry);
				}
			}
		}

		// Check if one of the certificates domains equals the host and report the result of that check
		if (!isValidForHost(domains, host)) {
			return new CertJudgment("<crit>CERT->DOMAIN: NOT VALID FOR " + host+"</crit>", -70);
		} else {
			return new CertJudgment("CERT->DOMAIN: ok", 50);
		}
	}

	/**
	 * Judge the keylength of a certificate. The outcome is always the keylength. Its rating depends on whether it is shorter or longer than 2048 ( which is the NIST suggestion until 2030:
	 * http://csrc.nist.gov/groups/ST/toolkit/documents/SP800-57Part1-Revision3_May2011.pdf). If it's shorter, then the rating is <0 and decreases quadratically with (keylength - 2048). If it is longer
	 * then the rating is >0 and increases linearly with (keylength - 2048).
	 * 
	 * @param cert
	 *            The certificate to judge
	 * @return A CertificateJudgment rating the certificates keylength based on the current keylength suggestion of BSI.
	 */
	private static CertJudgment getJudgmentOfKeyLength(X509Certificate cert){
		
		try{
		// Get the keylength of the Certificate's public key
		int keylength = ((RSAPublicKey) (cert.getPublicKey())).getModulus().bitLength();
		
		// Rate it deppending on the value of (keylength - 2048).
		int keylengthRating = (keylength - 2048 <0)? ((2048 - keylength)*(keylength - 2048))/30000:(keylength - 2048)/100;
		
		// Report the result
		if(keylengthRating<0){
			return new CertJudgment("<crit>KEYLENGTH: " + keylength + " BIT</crit>", keylengthRating);
		} else {
			return new CertJudgment("KEYLENGTH: " + keylength + " bit", keylengthRating);
		}
		
		} catch (ClassCastException e){
			return new CertJudgment("KEYLENGTH: no rsa key", 0);
		}
		
	}
	
	/**
	 * Judge the last continuous observation period of a certificate. There are two possible outcomes:
	 * - The period is not yet over (might even be 0 days since the certificate might never have been observed)
	 * - The period ended sometime in the past
	 * 
	 * @param cert The certificate for which the period should be determined
	 * @param hostPort The Hostname and port of the server from which it has been observed by the client e.g. encrypted.google.com:443 
	 * @param db The database connection to use
	 * @return A CertificateJudgment stating when was the last continuous observation period of the certificate
	 * @throws CertificateEncodingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidParameterException
	 * @throws SQLException
	 */
	private static CertJudgment getJudgmentOfLastObservationPeriod(X509Certificate cert, String hostPort, Database db) throws CertificateEncodingException, NoSuchAlgorithmException, InvalidParameterException, SQLException {
		
		// Calculate the certificate's SHA256-Hash
		byte[] certHash = CertificateManager.SHA256(cert.getEncoded());
		
		// Get all certificate ID's that share that hash
		String IDs = CertificateManager.getCertIDs(certHash,db);

		// Get the Timestamp of the last observation of the certificate for the host or the current time if it has never been observed (which would result in a LCOP of 0 days)
		Object[] params = { hostPort };
		    // WARNING (Ralph): you're interpolating a string
		    // it's probably OK because you're pulling IDs from the DB where it's guaranteed to be a hash value, but still...
		    // And you're using prepared statements, of course
		ResultSet rs = db.executeQuery("SELECT coalesce(MAX(Timeofobservation), 'NOW') AS Time FROM CertObservations WHERE ServerHostPort = ? AND CertID IN ("+IDs+") AND ObserverType = 'CrossbearServer'", params);

		if (!rs.next()) {
			throw new SQLException("Query returned invalid result.");
		}

		// Remember that Timestamp as endOfObservationPeriod
		Timestamp endOfObservationPeriod = rs.getTimestamp("Time");

		
		Object[] params2 = { hostPort, hostPort, endOfObservationPeriod };
		// Get the newest Timestamp of any certificate observation for the host that was not on the current certificate but is older than endOfObservationPeriod (or alternatively a very old dummy timestamp if there is none).
		String sqlSubQuery = "SELECT coalesce(MAX(TimeOfObservation), TIMESTAMP '1900-01-01 00:00') as Time FROM CertObservations WHERE ServerHostPort = ? AND CertID NOT IN ("+IDs+") AND ObserverType = 'CrossbearServer' and TimeOfObservation < ?";
		
		// Get the oldest Timestamp of any observation of the current certificate that is still newer than the Timestamp of the sub-querry
		    // WARNING (Ralph): you're interpolating a string
		    // it's probably OK because you're pulling IDs from the DB where it's guaranteed to be a hash value, but still...
		    // And you're using prepared statements, of course
		rs = db.executeQuery("SELECT coalesce(MIN(TimeOfObservation), 'NOW') as Time FROM CertObservations WHERE ServerHostPort = ? AND CertID IN ("+IDs+")  AND ObserverType = 'CrossbearServer' AND TimeOfObservation > (" + sqlSubQuery + ")", params2);

		if (!rs.next()) {
			throw new SQLException("Query returned invalid result.");
		}

		// Remember that Timestamp as beginOfObservationPeriod
		Timestamp beginOfObservationPeriod = rs.getTimestamp("Time");

		// Calculate how many days are between beginOfObservationPeriod and endOfObservationPeriod
		int observationdays = (int) ((endOfObservationPeriod.getTime() - beginOfObservationPeriod.getTime()) / (24 * 60 * 60 * 1000));
		
		// If endOfObservationPeriod is close to now claim that it is still being observed and return observationdays as LCOP
		if (Math.abs(endOfObservationPeriod.getTime() - System.currentTimeMillis()) < 300000) {

			int rating = observationdays / 3 * 2;

			return new CertJudgment("LCOP: " + observationdays + " days", rating);
			
		// Else return the precise begin and end of the observation period
		} else {
			
			int rating = observationdays /3;

			return new CertJudgment("LCOP: " + new Date(beginOfObservationPeriod.getTime()) + " - " + new Date(endOfObservationPeriod.getTime()), rating);
		}
	}
	
	/**
	 * Judge the total number of observations of a certificate for a host. There only possible outcome is the number of observations.
	 * 
	 * @param cert The certificate for which the total number of observations should be determined
	 * @param hostPort The Hostname and port of the server from which it has been observed by the client e.g. encrypted.google.com:443
	 * @param db The database connection to use
	 * @return A CertificateJudgment stating how often a certificate has already been observed for a host
	 * @throws CertificateEncodingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidParameterException
	 * @throws SQLException
	 */
	private static CertJudgment getJudgmentOfTotalNumberOfObservation(X509Certificate cert, String hostPort, Database db) throws CertificateEncodingException, NoSuchAlgorithmException, InvalidParameterException, SQLException {

		// Calculate the certificate's SHA256-Hash
		byte[] certHash = CertificateManager.SHA256(cert.getEncoded());
		
		// Get all certificate ID's that share that hash
		String IDs = CertificateManager.getCertIDs(certHash,db);
		
		// Get the total number of how often cert has been observed for hostPort by the CrossbearServer
		Object[] params = { hostPort };
		    // WARNING (Ralph): you're interpolating a string
		    // it's probably OK because you're pulling IDs from the DB where it's guaranteed to be a hash value, but still...
		    // And you're using prepared statements, of course
		ResultSet rs = db.executeQuery("SELECT COUNT(Id) as Num FROM CertObservations WHERE ServerHostPort = ? AND CertID IN ("+IDs+") AND ObserverType = 'CrossbearServer'", params);
		
		if (!rs.next()) {
			throw new SQLException("Query returned invalid result.");
		}
		
		// Remember the number and derive a rating from it
		long nomOfObservations = rs.getLong("Num");
		int rating = (int)(nomOfObservations/30);
		
		// Convert the number into its textual representation taking into account that the number might be very big and should be shortened
		String textualNumber = (nomOfObservations<1000)?String.valueOf(nomOfObservations):String.valueOf(nomOfObservations/1000)+"k";
		
		// Report the result
		return new CertJudgment("OBSERVATIONS: " + textualNumber, rating);
	}

	/**
	 * Judge the Signature Algorithm used by the certificate. There outcome is always the used algorithm. The rating depends on whether a deprecated algorithm is used or not.
	 * 
	 * @param cert The certificate for which the used algorithms should be judged
	 * @return A CertificateJudment judging the used signature algorithm of the certificate
	 */
	private static CertJudgment getJudgmentOfUsedAlgorithms(X509Certificate cert){
		
		// Extract the used signature algorithm from the certificate
		String sigAlg = cert.getSigAlgName();
		
		// Check if it contains a deprecated algorithm and generate a rating based on that
		Matcher m = deprecatedAlgPat.matcher(sigAlg);
		int rating = m.find()? -60 : 0;

		// Report the result
		if(rating<0){
			return new CertJudgment("<crit>ALGORITHM: " + sigAlg.toLowerCase()+"</crit>", rating);
		}
		else {
			return new CertJudgment("ALGORITHM: " + sigAlg.toLowerCase(), rating);
		}
		
	}

	/**
	 * Extract the commonName-part from a Distinguished Name
	 * 
	 * @param dn The Distinguised Name
	 * @return The commonName-part of the DN
	 */
	private static String getURLFromDN(String dn) {
		
		// Apply the pattern that matches the CN-part
		Matcher matcher = cnPat.matcher(dn.replaceAll("\\s", ""));
		
		// If it doesn't match then there is nothing to return
		if (!matcher.find())
			return "";

		// If it does: retrieve the matching string and return it
		String match = matcher.group();
		return match.substring(3, match.length());
	}
	
	/**
	 * After a certificate was judged and a CertVerifyResult was created it might be of use to create a Hunting Task on the server of the CertVerifyRequest. The decision if this is wanted or not is
	 * made here.
	 * 
	 * The current implementation of this function will return true if all of the following criteria are true:
	 * - comparison of the request's and the host's certificates resulted in a "different"-judgment
	 * - the certificate is also unknown to Convergence
	 * - the IP of the server is not the one of a SSL-Proxy
	 * - the host's IP is a normal unicast IP
	 * 
	 * In all other cases the function will return false.
	 * 
	 * @param request The Request that the client sent
	 * @param result The CertVerifyResult that has been created for the CertVerifyRequest
	 * @return True if a HuntingTask should be created else false
	 */
	private static boolean huntingTaskShouldBeCreated(CertVerifyRequest request, CertVerifyResult result) {
		
		// Did the comparison of the request's and the host's certificates resulted in a "different"-judgment and is the Certificate also unknown to Convergence?
		if(result.getReport().indexOf("CERTCOMPARE: DIFFERENT") == -1 || result.getReport().indexOf("CONVERGENCE: UNKNOWN") == -1){
			return false;
		}
		
		// Did the client set the "ssl-proxy"-bit
		if(request.isUserUsingProxy()){
			return false;
		}
			
		// Is the host's IP a link-local or a multicast address? If yes return false if not return true
		InetAddress hostIP = request.getHostIP();
		return !hostIP.isMulticastAddress() && !hostIP.isAnyLocalAddress() && !hostIP.isLinkLocalAddress() && !hostIP.isLoopbackAddress() && !hostIP.isSiteLocalAddress();
	}

	/**
	 * Check if a byte[] implements a valid Common Name in PASCAL-String representation. The two checks that are performed are:
	 * - is the length parameter correct
	 * - does it contain unprintable chars
	 * 
	 * @param cnBytes the byte[] to check
	 * @return true if the byte[] is a valid CN else false
	 */
	private static boolean isValidCN(byte[] cnBytes) {
		// Make sure the length attribute of the string is valid
		if (cnBytes.length != cnBytes[1] + 2)
			return false;

		// Make sure the CN contains printable chars only!
		for (int i = 2; i < cnBytes.length; i++) {
			if (cnBytes[i] < 32)
				return false;
		}

		return true;
	}

	/**
	 * Check if one of the domainPatterns matches the host
	 * 
	 * @param domainPatterns The domain patterns that might match the host (e.g. *.google.com, www.google.com)
	 * @param host The host to match (e.g. encrypted.google.com)
	 * @return True if one of the pattern matches else false
	 */
	private static boolean isValidForHost(Vector<String> domainPatterns, String host) {

		// Regex that matches all special chars
		Pattern specialCharPat = Pattern.compile("([^a-zA-Z0-9])");
		
		// String that will when compiled as Regex match all non-special chars 
		String validChars = "[a-zA-Z0-9-_]*";

		for (int i = 0; i < domainPatterns.size(); i++) {

			// Escape all special chars within the CN
			String escapedCn = specialCharPat.matcher(domainPatterns.get(i)).replaceAll("\\\\$1");

			// Replace "\*" with [a-zA-Z0-9-]*
			String cnAsRegex = escapedCn.replaceAll("\\\\\\*", validChars);

			// Try to match the pattern with the host and return true on success
			Pattern domainPat = Pattern.compile(cnAsRegex, Pattern.CASE_INSENSITIVE);
			Matcher domainMatcher = domainPat.matcher(host);
			if (domainMatcher.matches()) {
				return true;
			}
		}

		// If no pattern matched return failure
		return false;
	}

	/**
	 * Search the "Subject Alternative Name"-field (OID is 2.5.29.17) for Common Names and add all of them as byte[] to a Vector of byte[]s
	 * 
	 * @param altNames The DEROctetString found within the "Subject Alternative Name"-Field
	 * @param cnBytes The Vector to add all found CNs to
	 * @throws IOException
	 */
	private static void searchAltNamesForCN(DEROctetString altNames, Vector<byte[]> cnBytes) throws IOException {
		DERSequence altNameSequence = (DERSequence) DERSequence.fromByteArray(altNames.getOctets());

		// Look on the type of each element of the sequence
		for (int i = 0; i < altNameSequence.size(); i++) {
			DEREncodable altNameT = altNameSequence.getObjectAt(i);

			// Assert type of the element being a DERTaggedObject
			if (!(altNameT instanceof DERTaggedObject))
				continue;

			// Extract the content of the DERTaggedObject
			DERObject altNameO = ((DERTaggedObject) altNameT).getObject();

			// Assert type of the content being a DEROctetString
			if (!(altNameO instanceof DEROctetString))
				continue;

			// Extract name field and store it
			cnBytes.add(((DEROctetString) altNameO).getEncoded());
		}
	}

	/**
	 * Search a DERSequence for all occurrences of Common Names. They might be stored in the "Subject Alternative Name"-field (OID is 2.5.29.17) or in a commonName-field (OID is 2.5.4.3)
	 * 
	 * @param seq The sequence to be searched (might be created by calling  DERSequence.fromByteArray(X509Certificate.getEncoded()))
	 * @param cnBytes The Vector to add all found CNs to
	 * @throws IOException
	 */
	private static void searchSequenceForCNs(DERSequence seq, Vector<byte[]> cnBytes) throws IOException  {

		// Look on the type of each element of the sequence
		for (int i = 0; i < seq.size(); i++) {
			DEREncodable derEncodable = seq.getObjectAt(i);

			// if the type is a DERSequence (i.e. a subsequence) then check if starts with an OID or not
			if (derEncodable instanceof DERSequence) {
				DEREncodable firstSubSequenceElement = ((DERSequence) derEncodable).getObjectAt(0);

				// If it starts with an OID and If the OID is 2.5.29.17 then we found the "Subject Alternative Name"-field
				if ((firstSubSequenceElement instanceof ASN1ObjectIdentifier) && ((ASN1ObjectIdentifier) firstSubSequenceElement).getId().equals("2.5.29.17")) {
					DEREncodable secondSubSequenceElement = ((DERSequence) derEncodable).getObjectAt(1);

					// Assert type of SAN-field being an octetString
					if (secondSubSequenceElement instanceof DEROctetString) {
						searchAltNamesForCN((DEROctetString) secondSubSequenceElement, cnBytes);
					}

					// If not just continue recursively
				} else {
					searchSequenceForCNs((DERSequence) derEncodable, cnBytes);
				}

				// If the type is a DERSet then we might be close to the CN-Field -> try to extract it
			} else if (derEncodable instanceof DERSet) {
				searchSetForCN((DERSet) derEncodable, cnBytes);

				// If the type is a DERTaggedObject then we might have found the Extension of the certificate
			} else if (derEncodable instanceof DERTaggedObject) {
				int tagno = ((DERTaggedObject) derEncodable).getTagNo();

				// The tag for the extension we are looking for is 3
				if (tagno == 3) {
					DERObject exensionList = ((DERTaggedObject) derEncodable).getObject();

					// Assert type of the extension being a DERSequence
					if (exensionList instanceof DERSequence) {
						searchSequenceForCNs((DERSequence) exensionList, cnBytes);
					}
				}
			}
		}

	}
	
	/**
	 * Search a DERSet for Common Names (identified by OID 2.5.4.3) and add all of them as byte[] to a Vector of byte[]s
	 * 
	 * @param set The DERSet to search
	 * @param cnBytes The Vector to add all found CNs to
	 * @throws IOException
	 */
	private static void searchSetForCN(DERSet set, Vector<byte[]> cnBytes) throws IOException {

		// The DERSet we are looking for contains exactly one element: a DERSequence
		if (set.size() != 1 || !(set.getObjectAt(0) instanceof DERSequence))
			return;

		// Extract the DERSequence
		DERSequence subseq = (DERSequence) set.getObjectAt(0);

		// The DERSequence we are looking for consists of two elements: an OID and the CN
		// First: Assert type of OID
		if (!(subseq.getObjectAt(0) instanceof ASN1ObjectIdentifier))
			return;

		// Second: Check value of OID to be id-at-commonName
		ASN1ObjectIdentifier id = (ASN1ObjectIdentifier) subseq.getObjectAt(0);
		if (!id.getId().equals("2.5.4.3"))
			return;

		// Third extract the commonName
		cnBytes.add(subseq.getObjectAt(1).getDERObject().getEncoded());
	}
	
	// The CertVerifyRequest that should be processed by this processor
	private CertVerifyRequest cvr;
	
	// The CertificateManager that will be used for processing or storing certificates
	private CertificateManager cm;

	// The Database connection to use
	private Database db;

	/**
	 * Create a new CVRProcessor
	 * 
	 * @param cvr The CertVerifyRequest that it will process
	 * @param cm The CertificateManager that it will use for processing or storing certificates
	 * @param db The Database connection that it will use
	 */
	public CVRProcessor(CertVerifyRequest cvr, CertificateManager cm, Database db) {
		this.cvr = cvr;
		this.cm = cm;
		this.db = db;
	}

	/**
	 * Try to retrieve a CertVerifyResult from the local cache i.e. the CertVerifyResultCache-table
	 * 
	 * A match will only be found if the CertVerifyRequest of this CVRProcessor is a duplicate.
	 * 
	 * @return The bytes of the CertVerifyResult
	 * @throws InvalidParameterException
	 * @throws SQLException
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 */
    public byte[] getCachedCertVerifyResult() throws InvalidParameterException, SQLException, IOException, NoSuchAlgorithmException, MessageSerializationException {

		// The KEY of the CertVerifyResultCache-table is a hash of the corresponding CertVerifyRequest.
		Object[] params = { Message.byteArrayToHexString(cvr.getHash()) };
		ResultSet rs = db.executeQuery("SELECT * FROM CertVerifyResultCache WHERE Hash = ? LIMIT 1", params);

		// If the result is empty then there is no cache entry to return
		if (!rs.next()) {
			return null;
		}

		// If the cache entry is not valid anymore then there is nothing to return
		Timestamp validUntil = rs.getTimestamp("ValidUntil");
		if (validUntil.before(new Timestamp(System.currentTimeMillis())))
			return null;

		// If there is a cache entry that is currently valid: return its bytes.
		return rs.getBytes("Bytes");

	}
	
	/**
	 * The process takes as input a CertVerifyRequest and judges its certificate based on various criteria. It returns a MessageList consisting of a CertVerifyResult and optionally a
	 * CurrentServerTime-message a PublicIPNotification-message and a HuntingTask-message if the CertVerifyResult is worth creating a hunting task.
	 * 
	 * Currently the Judgments that are made are
	 * - Is the certificate that was observed by the client equal to the one that was observed by the server?
	 * - What was the last period of continuous observation for the certificate?
	 * - How often has the certificate already been observed?
	 * - What is the period during which Convergence observed the certificate?
	 * - Is the certificate valid for the domain on which it was observed?
	 * - Is the certificate currently valid?
	 * - Are the used encryption algorithms deprecated?
	 * - Is the keylength long enough?
	 * 
	 * @return The message list described above
	 * @throws InvalidParameterException
	 * @throws NoSuchAlgorithmException
	 * @throws SQLException
	 * @throws KeyManagementException
	 * @throws InvalidAlgorithmParameterException
	 * @throws KeyStoreException
	 * @throws CertificateException
	 * @throws NoSuchProviderException
	 * @throws IOException
	 * @throws InvalidKeyException 
	 */
	public MessageList process() throws InvalidParameterException, NoSuchAlgorithmException, SQLException, KeyManagementException, InvalidAlgorithmParameterException, KeyStoreException, CertificateException, NoSuchProviderException, IOException, InvalidKeyException {

		// Get the certificate that the client sent
		X509Certificate requestCert = cm.getCertFromRequest(cvr, db);

		// Try to get the server's real certificate ...
		 X509Certificate serverCert = cm.getCertForHost(cvr, db);

		//concatenate hostname and hostport to hostport. Hostport is the host's identifier in the database
		String hostPort = cvr.getHostName()+":"+String.valueOf(cvr.isUserUsingProxy()?443:cvr.getHostPort());
		
		MessageList ml = new MessageList();

		CertVerifyResult result = new CertVerifyResult();

		// Top line: which is the name for which the certificate was issued
		result.addJudgment(new CertJudgment("DOMAIN: " + getURLFromDN(requestCert.getSubjectDN().getName()), 0));

		// Did the server get the same certificate as the client?
		result.addJudgment(getJudgmentOfCertEquality(serverCert, requestCert));

		// What was the last interval the server observed this certificate?
		result.addJudgment(getJudgmentOfLastObservationPeriod(requestCert, hostPort, db));

		// How often has the server already observed this certificate?
		result.addJudgment(getJudgmentOfTotalNumberOfObservation(requestCert, hostPort, db));
		
		// What is the period during which Convergence observed the certificate?
		result.addJudgment(new ConvergenceConnector(db, 1000*60*60*6).getJudgmentOfObservationPeriod(requestCert, hostPort));

		// Has the certificate been issued for the requesting domain?
		result.addJudgment(getJudgmentOfDomainMatch(requestCert, cvr.getHostName()));

		// Is the certificate currently valid?
		result.addJudgment(getJudgmentOfCurrentValidity(requestCert));

		// What are the used encryption/hash algorithms? Are they safe? (some algorithms like e.g. md2 and md5 are not considered safe anymore)
		result.addJudgment(getJudgmentOfUsedAlgorithms(requestCert));

		// What is the length of the key? (NIST suggests at least 2048 until 2030: http://csrc.nist.gov/groups/ST/toolkit/documents/SP800-57Part1-Revision3_May2011.pdf)
		result.addJudgment(getJudgmentOfKeyLength(requestCert));

		ml.add(result);

		// Is the result such that a Hunting Task should be created?
		if (huntingTaskShouldBeCreated(cvr, result)) {
			ml.add(new CurrentServerTime());
			ml.add(new PublicIPNotification(cvr.getRemoteAddr(), db));
			ml.add(new HuntingTask(cvr.getHostName(), cvr.getHostIP(), cvr.isUserUsingProxy()?443:cvr.getHostPort(), db));
		}

		return ml;

	}

	/**
	 * Since every CertVerifyResult is written into the cache (i.e. the CertVerifyResultCache-table) it might become very big after a while. To prevent this from happening, the cache is purged every
	 * once in a while. Purging in this context means removing all entries from the database that are no longer valid.
	 * 
	 * @throws InvalidParameterException
	 * @throws SQLException
	 */
	public void purgeCache() throws InvalidParameterException, SQLException{
		
		Object[] params = {new Timestamp(System.currentTimeMillis()) };
		db.executeUpdate("DELETE FROM CertVerifyResultCache WHERE ValidUntil < ?", params);
		
	}

	/**
	 * Store a CertVerifyResult in the local certificate cache (i.e. the CertVerifyResultCache-table). The local CertVerifyResult cache is used to reduce the load of the server and to prevent
	 * duplicate observations from being inserted into the database
	 * 
	 * @param result The bytes of the CertVerifyResult to store
	 * @param validity The time in milliseconds that the entry should stay valid
	 * @throws InvalidKeyException
	 * @throws CertificateEncodingException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws IOException
	 * @throws SQLException
	 */
    public void storeCertVerifyResultInCache(byte[] result, long validity) throws InvalidKeyException, CertificateEncodingException, NoSuchAlgorithmException, NoSuchProviderException, IOException, SQLException, MessageSerializationException{
		
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
				Object[] params = { result, new Timestamp(System.currentTimeMillis() + validity), Message.byteArrayToHexString(cvr.getHash()) };
				int updatedRows = db.executeUpdate("UPDATE CertVerifyResultCache SET Bytes = ?, ValidUntil = ? WHERE Hash = ?", params);

				// If there isn't any try to insert a new one.
				if (updatedRows == 0) {
					db.executeInsert("INSERT INTO CertVerifyResultCache (Bytes,ValidUntil,Hash) VALUES (?,?,?)", params);
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

}
