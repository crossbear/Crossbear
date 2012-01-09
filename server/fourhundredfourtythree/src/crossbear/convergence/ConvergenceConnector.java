/*
 * Copyright (c) 2011, Thomas Riedmaier, TU München
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Crossbear nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THOMAS RIEDMAIER BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package crossbear.convergence;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.sql.Date;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.HashSet;
import java.util.Iterator;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import crossbear.CertJudgment;
import crossbear.CertificateManager;
import crossbear.Database;
import crossbear.TrustSingleCertificateTM;
import crossbear.messaging.Message;

/**
 * The Convergence Project (http://convergence.io/) which was initially created by Moxie Marlinspike provides a functionality that is quite similar to Crossbear's Guard-functionality: Comparison based
 * certificate verification by the use of distributed observation points. Crossbear utilizes Convergence's functionality to make the report it gives about a certificate more accurate. To do so
 * Crossbear queries the Convergence project every time it judges a certificate and adds Convergence's judgment as an additional judgment to the certificate's report.
 * 
 * The details about this process are as follows: When queried for a host Convergence will respond with a list of ConvergenceCertificateObservations of the form
 * {"timestamp":{"finish":"1318361407","start":"1317392198"},"fingerprint":"56:F6:A9:A9:D2:ED:FD:1A:B2:F9:63:7E:D3:51:AC:56:B3:59:A9:8D"}. Due to the lack of sourcecode I am bound to assume that these
 * ConvergenceCertificateObservations depict the information about when a certificate was observed for that host. Based on this assumption I implemented the following algorithm: 
 * - When a new certificate is to be checked, ask Convergence about which certificates it has observed for the certificate's host 
 * - Store the whole list in the ConvergenceCertObservations-table 
 * - Search the list for the certificate that the Crossbear-client observed and if there is a entry for it build a CertJudgment based on that.
 * 
 * In order to keep the load on the Convergence-Project at a minimum the algorithm above uses caching. To be precise Convergence is only contacted when there is no reasonably new entry about a
 * certificate/host combination in the ConvergenceCertObservations-table. If Convergence has never observed a certificate (which will e.g. be the case for SNI-servers) this fact is also cached.
 * 
 * This class implements the algorithm that I just described.
 * 
 * @author Thomas Riedmaier
 * 
 */
public class ConvergenceConnector {


	/**
	 * Contact a ConvergenceNotary and ask it for all information about certificate observations it has made on a specific host.
	 * 
	 * Please note: Contacting a ConvergenceNotary is possible with and without sending the fingerprint of the observed certificate. In both cases the Notary will send a list of
	 * ConvergenceCertificateObservations. The problem is that if no fingerprint is sent or the fingerprint matches the last certificate that the Notary observed for the host, the Notary will just
	 * read the list of ConvergenceCertificateObservations from its database. It will not contact the server to see if it the certificate is still the one it uses. The problem with that is that with
	 * this algorithm Convergence usually makes only one certificate observation per server. When asked for that server a Notary will therefore reply "I saw that certificate last July". Since
	 * Crossbear requires statements like "I saw this certificate since last July" it will send a fake-fingerprint to the Convergence Notaries. This compels the Notary to query the server for
	 * its current certificate. After that the Notary will update its database and will then send the updated list of ConvergenceCertificateObservations to Crossbear.
	 * 
	 * @param notary
	 *            The notary to contact
	 * @param hostPort
	 *            The Hostname and port of the server on which the information about the certificate observations is desired.
	 * @return The Response-String that the Notary sent as an answer. It will contain a JSON-encoded list of ConvergenceCertificateObservations
	 * @throws IOException
	 * @throws KeyManagementException
	 * @throws NoSuchAlgorithmException
	 */
	private static String contactNotary(ConvergenceNotary notary, String hostPort) throws IOException, KeyManagementException, NoSuchAlgorithmException {

		// Construct a fake fingerprint to send to the Notary (currently the Hex-String representation of "ConvergenceIsGreat:)")
		String data = "fingerprint=43:6F:6E:76:65:72:67:65:6E:63:65:49:73:47:72:65:61:74:3A:29"; 

		// Build the url to connect to based on the Notary and the certificate's host
		URL url = new URL("https://" + notary.getHostPort() + "/target/" + hostPort.replace(":", "+"));
		
		// Open a HttpsURLConnection for that url
		HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();

		/*
		 * Set a TrustManager on that connection that forces the use of the Notary's certificate. If the Notary sends any certificate that differs from the one that it is supposed to have (according
		 * to the ConvergenceNotaries-table) an Exception will be thrown. This protects against Man-in-the-middle attacks placed between the Crossbear server and the Notary.
		 */
		SSLContext sc = SSLContext.getInstance("SSL");
		sc.init(null, new TrustManager[] { new TrustSingleCertificateTM(Message.hexStringToByteArray(notary.getCertSHA256Hash())) }, new java.security.SecureRandom());
		conn.setSSLSocketFactory(sc.getSocketFactory());

		// Set the timeout during which the Notary has to reply
		conn.setConnectTimeout(3000);
		
		// POST the fake fingerprint to the Notary
		conn.setDoOutput(true);
		OutputStreamWriter wr = new OutputStreamWriter(conn.getOutputStream());
		wr.write(data);
		wr.flush();

		// Get the Notary's response. Since Convergence replies with a 409-error if it has never observed a certificate conn.getInputStream() will be null. The way to get the Notarys reply in that case is to use conn.getErrorStream().
		InputStream is;
		if (conn.getResponseCode() >= 400) {
			is = conn.getErrorStream();

		} else {
			// This line should never be executed since we send a fake fingerprint that should never belong to an actually observed certificate. But who knows ...
			is = conn.getInputStream();
		}

		// Read the Notary's reply and store it
		String response = Message.inputStreamToString(is);

		// Close all opened streams
		wr.close();

		// Return the Notary's reply
		return response;

	}

	/**
	 * Get the ConvergenceCertObservation from a Set of ConvergenceCertObservations whose certificate has a specific SHA1-hash
	 * 
	 * @param certSHA1 The SHA1-hash of the certificate of the ConvergenceCertObservation that should be returned
	 * @param hostCcos A Set of ConvergenceCertObservations
	 * @return The ConvergenceCertObservation whose certificate has a SHA1-hash that matches "certSHA1". If there is no ConvergenceCertObservation in the set for which this is true then null is returned.
	 */
	private static ConvergenceCertObservation getCCOFromList(String certSHA1, HashSet<ConvergenceCertObservation> hostCcos) {

		// Go through the whole set ...
		Iterator<ConvergenceCertObservation> itr = (Iterator<ConvergenceCertObservation>) hostCcos.iterator();
		while (itr.hasNext()) {
			
			// .. and check for each ConvergenceCertObservation ...
			ConvergenceCertObservation cco = itr.next();
			
			// .. if the SHA1-hash of its certificate matches "certSHA1".
			if (cco.getCertHash().equals(certSHA1)) {
				
				// If yes: return it.
				return cco;
			}
		}

		// If there was no suitable ConvergenceCertObservation in the set: return null
		return null;
	}

	/**
	 * Make a Judgment on a ConvergenceCertObservation. The Judgment will be based on
	 * - How Long did Convergence observe the certificate for the Host?
	 * - Does it currently observe the certificate for the Host?
	 * 
	 * @param cco The ConvergenceCertObservation to Judge
	 * @return A Judgment for "cco"
	 */
	private static CertJudgment getJudgmentForCCO(ConvergenceCertObservation cco) {

		// If "cco" is a dummy entry then Convergence has never observed the Certificate: return this information
		if (cco.getFirstObservation().equals(new Timestamp(0)) && cco.getLastObservation().equals(new Timestamp(0))) {
			return new CertJudgment("<crit>CONVERGENCE: UNKNOWN</crit>", -20);
		}

		// Calculate how many days are between lastObservation and firstObservation
		int observationdays = (int) ((cco.getLastObservation().getTime() - cco.getFirstObservation().getTime()) / (24 * 60 * 60 * 1000));

		// If lastObservation is close to now claim that it is still being observed and return observationdays as "how long it has been observed"
		if (Math.abs(cco.getLastObservation().getTime() - System.currentTimeMillis()) < 1000 * 60 * 60 * 24) {

			int rating = observationdays / 3 * 2;

			return new CertJudgment("CONVERGENCE: Seen for " + observationdays + " days", rating);

			// Else return the precise begin and end of the observation period
		} else {

			int rating = observationdays / 3;

			return new CertJudgment("CONVERGENCE: Seen from " + new Date(cco.getFirstObservation().getTime()) + " - " + new Date(cco.getLastObservation().getTime()), rating);
		}
	}

	/**
	 * Transfer the Notary's answer from a JSON-representation into a HashSet of ConvergenceCertObservation
	 * 
	 * @param notaryAnswer The Response-String that the Notary sent as an answer. It should contain a JSON-encoded list of ConvergenceCertificateObservations 
	 * @param hostPort The Hostname and port of the server on which the information about the certificate observations is desired.
	 * @return The Notary's answer as a Set of ConvergenceCertObservations
	 * @throws ParseException
	 */
	private static HashSet<ConvergenceCertObservation> parseNotaryAnswer(String notaryAnswer, String hostPort) throws ParseException {

		// Create a empty Set of ConvergenceCertObservations
		HashSet<ConvergenceCertObservation> re = new HashSet<ConvergenceCertObservation>();

		// Try to decode the Notary's answer as a JSONObject
		JSONParser parser = new JSONParser();
		JSONObject obj = (JSONObject) parser.parse(notaryAnswer);

		// If that worked extract the field called fingerprintList (which is basically a list of ConvergenceCertObservations in JSON encoding)
		JSONArray array = (JSONArray) obj.get("fingerprintList");

		// Go through the list ...
		for (int i = 0; i < array.size(); i++) {
			
			// ... read each entry ...
			JSONObject entry = (JSONObject) array.get(i);
			
			// .. extract its content ...
			byte[] fingerprint = Message.hexStringToByteArray(((String) entry.get("fingerprint")).replace(":", ""));
			JSONObject ts = (JSONObject) entry.get("timestamp");
			Timestamp firstObservation = new Timestamp(1000 * Long.valueOf((String) ts.get("start")));
			Timestamp lastObservation = new Timestamp(1000 * Long.valueOf((String) ts.get("finish")));
			Timestamp lastUpdate = new Timestamp(System.currentTimeMillis());

			// ... and create a new ConvergenceCertObservation-object based on that content.
			re.add(new ConvergenceCertObservation(hostPort, Message.byteArrayToHexString(fingerprint), firstObservation, lastObservation, lastUpdate));
		}

		// Finally return the Set containing all of the extracted ConvergenceCertObservations.
		return re;
	}

	// The Database connection to use
	private Database db;

	/* 
	 * Crossbear wants to keep the load on Convergence as low as possible. Therefore it caches all information it receives from Convergence. 
	 * The time interval that will minimally pass between two identical requests to Convergence can be set here (will be interpreted as ms)
	 */
	private int refreshInterval;

	/**
	 * Establish a new Connection to the Convergence Project
	 * 
	 * @param db The Database connection to use
	 * @param refreshInterval The time interval that will minimally pass between two identical requests to Convergence (in ms)
	 */
	public ConvergenceConnector(Database db, int refreshInterval) {
		this.db = db;
		this.refreshInterval = refreshInterval;
	}

	/**
	 * Try to retrieve a ConvergenceCertObservation from the local cache i.e. the ConvergenceCertObservations-table
	 * 
	 * @param hostPort The Hostname and port of the server from which a questionable certificate has been received 
	 * @param certSHA1 The SHA1-hash of the questionable certificate
	 * @return If known (and not archaic): The ConvergenceCertObservation for the "hostPort"/"certSHA1"-combination, else null
	 * @throws SQLException
	 */
	private ConvergenceCertObservation getCCOFromCache(String hostPort, String certSHA1) throws SQLException {

		Object[] params = { hostPort, certSHA1 };
		ResultSet rs = db.executeQuery("SELECT * FROM ConvergenceCertObservations WHERE ServerHostPort = ? AND SHA1Hash = ? LIMIT 1", params);

		// If the result is empty then there is no cache entry to return
		if (!rs.next()) {
			return null;
		}

		// If the cache entry is not valid anymore (and should be refreshed) then there is nothing to return
		Timestamp lastUpdate = rs.getTimestamp("LastUpdate");
		if (lastUpdate.before(new Timestamp(System.currentTimeMillis() - this.refreshInterval)))
			return null;

		// If there is a cache entry that is currently valid: return it as ConvergenceCertObservation
		return new ConvergenceCertObservation(rs.getString("ServerHostPort"), rs.getString("SHA1Hash"), rs.getTimestamp("FirstObservation"), rs.getTimestamp("LastObservation"), lastUpdate);
	}

	/**
	 * Contact a ConvergenceNotary and get all of the ConvergenceCertObservations it has made on a specific server
	 * 
	 * @param hostPort The Hostname and port of the server for which the ConvergenceCertObservations are desired
	 * @return A Set of all the ConvergenceCertObservations that the Notary has made on "hostPort". If an error occurred null will be returned
	 */
	private HashSet<ConvergenceCertObservation> getCCOsForHostPort(String hostPort) {

		try {
			// Get a random ConvergenceNotary from the ConvergenceNotaries-table
			ConvergenceNotary notary = getRandomConvergenceNotary();

			// Contact it and ask it about ConvergenceCertObservations for "hostPort"
			String notaryAnswer = contactNotary(notary, hostPort);

			// Try to decode the Notary's JSON-encoded answer and convert it into a Set of ConvergenceCertObservations
			return parseNotaryAnswer(notaryAnswer, hostPort);

		} catch (KeyManagementException | NoSuchAlgorithmException | IOException | ParseException | SQLException e) {
			return null;
		}

	}

	/**
	 * Judge the Convergence's observation period of a certificate. There are four possible outcomes:
	 * - The period is not yet over
	 * - The period ended sometime in the past
	 * - The certificate has never been observed by Convergence
	 * - The Convergence Notary didn't reply (e.g. because of a timeout or because the Notary was not able to get the server's certificate)
	 * 
	 * @param cert The certificate for which the period should be determined
	 * @param hostPort The Hostname and port of the server from which it has been observed by the client e.g. encrypted.google.com:443 
	 * @return A CertificateJudgment stating during which time interval Convergence observed "cert" for "hostPort"
	 * @throws SQLException
	 * @throws CertificateEncodingException
	 * @throws NoSuchAlgorithmException
	 */
	public CertJudgment getJudgmentOfObservationPeriod(X509Certificate cert, String hostPort) throws SQLException, CertificateEncodingException, NoSuchAlgorithmException {

		// Calculate the certificate's SHA1-hash. It will be used as the certificate's identifier in all Convergence-related functions and SQL-tables
		String certSHA1 = Message.byteArrayToHexString(CertificateManager.SHA1(cert.getEncoded()));

		// Try to get the information about when Convergence observed "cert" for "hostPort" from the local cache (i.e. the ConvergenceCertObservations-table)
		ConvergenceCertObservation cco = getCCOFromCache(hostPort, certSHA1);

		// If that was not possible ...
		if (cco == null) {

			// ... contact a ConvergenceNotary for all ConvergenceCertObservations it made for "hostPort".
			HashSet<ConvergenceCertObservation> hostCcos = getCCOsForHostPort(hostPort);

			// If that failed also: Report that it was not possible to get a Judgment from Convergence.
			if (hostCcos == null) {
				return new CertJudgment("CONVERGENCE: NO REPLY", 0);
			}

			// In case it was possible: See if convergence has ever observed "cert"
			cco = getCCOFromList(certSHA1, hostCcos);
			
			// If not ...
			if(cco == null){
				// .. create a dummy-observation for the "hostPort"/"cert"-combination. This is necessary in order to store the fact that Convergence has never observed "cert" for "hostPort" in the local cache.
				cco = new ConvergenceCertObservation(hostPort, certSHA1, new Timestamp(0), new Timestamp(0), new Timestamp(System.currentTimeMillis()));
				
				// Add the dummy-observation in "hostCcos" so it will be added to the cache
				hostCcos.add(cco);
			}
			
			// Add all ConvergenceCertObservations that the server made for "hostPort" in the local cache
			storeCCOsInCache(hostCcos);


		}

		// Finally get a Judgment for the ConvergenceCertObservations made for the "hostPort"/"cert"-combination and return it
		return getJudgmentForCCO(cco);
	}

	/**
	 * Select a random ConvergenceNotary from the ConvergenceNotaries-table and return it
	 * 
	 * @return A random ConvergenceNotary from the ConvergenceNotaries-table
	 * @throws SQLException
	 */
	private ConvergenceNotary getRandomConvergenceNotary() throws SQLException {
		
		// Reqeust a random Notary from the ConvergenceNotaries-table
		ResultSet rs = db.executeQuery("SELECT * FROM ConvergenceNotaries ORDER BY RANDOM() LIMIT 1", new Object[] {});

		// If the result is empty then there is no ConvergenceNotary Crossbear could use
		if (!rs.next()) {
			return null;
		}

		// Build a ConvergenceNotary-based on the reply from the database and return it
		return new ConvergenceNotary(rs.getString("HostPort"), rs.getString("CertID"));
	}

	/**
	 * Store a ConvergenceCertObservation in the local cache (i.e. the ConvergenceCertObservations-table). The local ConvergenceCertObservation-cache is used to reduce the network traffic generated by
	 * Crossbear, to reduce the load on Convergence and to speed up the average response time of Certificate Verification Requests.
	 * 
	 * @param cco The ConvergenceCertObservation to store
	 * @throws SQLException
	 */
	private void storeCCOInCache(ConvergenceCertObservation cco) throws SQLException {

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
				Object[] params = { cco.getFirstObservation(), cco.getLastObservation(), cco.getLastUpdate(), cco.getHostPort(), cco.getCertHash() };
				int updatedRows = db
						.executeUpdate("UPDATE ConvergenceCertObservations SET FirstObservation = ?, LastObservation = ?, LastUpdate = ? WHERE ServerHostPort = ? AND SHA1Hash = ?", params);

				// If there isn't any try to insert a new one.
				if (updatedRows == 0) {
					db.executeInsert("INSERT INTO ConvergenceCertObservations (FirstObservation,LastObservation,LastUpdate,ServerHostPort,SHA1Hash) VALUES (?,?,?,?,?)", params);
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

	
	/**
	 * Store a set of ConvergenceCertObservations in the local cache (i.e. the ConvergenceCertObservations-table). The local ConvergenceCertObservation-cache is used to reduce the network traffic generated by
	 * Crossbear, to reduce the load on Convergence and to speed up the average response time of Certificate Verification Requests.
	 * 
	 * @param ccos The set of ConvergenceCertObservations that is to store in the local cache
	 * @throws SQLException
	 */
	private void storeCCOsInCache(HashSet<ConvergenceCertObservation> ccos) throws SQLException {

		// Iterate over the whole set ...
		Iterator<ConvergenceCertObservation> itr = (Iterator<ConvergenceCertObservation>) ccos.iterator();
		while (itr.hasNext()) {
			
			// ... and add each of its elements to the local cache
			storeCCOInCache(itr.next());
		}

	}

}