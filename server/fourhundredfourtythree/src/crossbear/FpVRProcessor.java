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
import java.security.InvalidParameterException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import crossbear.messaging.FpVerifyRequest;
import crossbear.messaging.FpVerifyResult;
import crossbear.messaging.FpVerifyResult.FpVerifyResults;
import crossbear.messaging.MessageList;

/**
 * The FpVRProcessor takes as input a FpVerifyRequest and checks if the SSH host key fingerprint corresponds
 * to the one in the database or fetched live from the remote host.
 * 
 * @author Thomas Riedmaier
 * @author Oliver Gasser
 * 
 */
public class FpVRProcessor {
	
	// Timeout in milliseconds for fetching an SSH host key fingerprint live
	private static final long SSH_FETCH_TIMEOUT_MS = 500;

	// The FpVerifyRequest that should be processed by this processor
	private FpVerifyRequest fpvr;
	
	// The Database connection to use
	private Database db;
	
	// Properties
	Properties properties;
	
	// Should the SSH host key fingerprint be fetched live from the remote host
	private static final boolean DO_ONLINE_CHECK = true;
	
	// Should the database be update with the fetched data
	private static final boolean DO_UPDATE_DB = false;

	/**
	 * Create a new FpVRProcessor
	 * 
	 * @param fpvr The FpVerifyRequest that it will process
	 * @param db The Database connection that it will use
	 */
	public FpVRProcessor(FpVerifyRequest fpvr, Database db) {
		this.fpvr = fpvr;
		this.db = db;
		try {
			this.properties = new Properties("/opt/apache-tomcat/webapps/crossbear.properties");
		} catch (IOException e) {
		}
	}
	
	/**
	 * Retrieves the fingerprint corresponding to the request from the database.
	 * 
	 * @return Fingerprint object matching the IP, port, key type from the FpVR
	 * @throws InvalidParameterException
	 * @throws SQLException
	 */
	private Fingerprint getFingerprintFromDatabase() throws InvalidParameterException, SQLException {
		
		Object[] params = { fpvr.getHostIP(), Integer.valueOf(fpvr.getHostPort()), Ssh.keyTypeToString(fpvr.getKeyType(), fpvr.getKeyNid()) };
		
		ResultSet rs = db.executeQuery("SELECT fingerprint, ts FROM hosts JOIN ssh2 ON hosts.id = ssh2.host_id WHERE ip_addr = inet(?) AND port = ? AND host_key_type = ? ORDER BY ts DESC", params);
		
		// No entry was found in DB
		if (!rs.next()) {
			return null;
		}
		
		String fp = rs.getString("fingerprint");
		Timestamp ts = rs.getTimestamp("ts");
		
		return new Fingerprint(fp, ts);
	}
	
	/**
	 * Extracts the fingerprint from the request.
	 * 
	 * @return Fingerprint object created from the FpVR
	 */
	private Fingerprint getFingerprintFromRequest() {
		return new Fingerprint(fpvr.getFingerprint());
	}
	
	/**
	 * Inserts a fingerprint object into the database.
	 * 
	 * @param fp Fingerprint object to be inserted
	 */
	private void insertFpIntoDatabase(Fingerprint fp) {
		//TODO
	}
	
	/**
	 * Checks whether the fingeprint should be fetched live from the remote server.
	 * 
	 * @param requestFp Fingerprint from the request
	 * @param databaseFp Fingerprint from the database
	 * @return True if a the fingerprint should be fetched live, false otherwise
	 */
	private boolean doOnlineFpFetching(Fingerprint requestFp, Fingerprint databaseFp) {
		if (!DO_ONLINE_CHECK) {
			return false;
		}
		
		return (databaseFp == null) || !databaseFp.isTimestampValid() || !requestFp.equals(databaseFp);
	}
	
	
	/**
	 * The FpVRProcessor takes as input a FpVerifyRequest and checks if the SSH host key fingerprint corresponds
	 * to the one in the database or fetched live from the remote host.
	 * 
	 * @return Message list consisting of one FpVerifyResult message.
	 * @throws InvalidParameterException
	 * @throws SQLException
	 */
	public MessageList process() throws InvalidParameterException, SQLException  {

		// Get fingerprints
		Fingerprint requestFp = getFingerprintFromRequest();
		Fingerprint databaseFp = getFingerprintFromDatabase();
		Fingerprint onlineFp = null;
		
		// Online fetching of SSH host key fingerprint
		if (doOnlineFpFetching(requestFp, databaseFp)) {
			
			onlineFp = Ssh.fetchSshFp(fpvr.getHostIP(), fpvr.getHostPort(), fpvr.getKeyType(), fpvr.getKeyNid(), SSH_FETCH_TIMEOUT_MS);
			
			if (DO_UPDATE_DB) {
				insertFpIntoDatabase(onlineFp);
			}
			
			databaseFp = onlineFp;
		}
		
		// Calculate result
		FpVerifyResults result;
		if (databaseFp == null) {
			result = FpVerifyResults.NO_ENTRY;
		} else if (requestFp.equals(databaseFp)){
			result = FpVerifyResults.MATCH;
		} else {
			result = FpVerifyResults.NO_MATCH;
		}
		
		// Create response		
		MessageList ml = new MessageList();
		FpVerifyResult fpvr = new FpVerifyResult();
		fpvr.setResult(result);
		ml.add(fpvr);
		
		return ml;
	}
}

/**
 * Class representing a fingerprint, consisting of fingerprint value and timestamp.
 * 
 * @author Oliver Gasser
 *
 */
class Fingerprint {
	
	// Fingerprints are valid for one week (in milliseconds)
	private static final long FP_VALIDITY_MS = 7l * 24l * 60l * 60l * 1000l;
	
	// Fingerprint value
	private String fingerprint;
	
	// Timestamp when the fingerprint was fetched
	private Timestamp time;
	
	public Fingerprint(String fingerprint) {
		this(fingerprint, null);
	}
	
	public Fingerprint(String fingerprint, Timestamp time) {
		this.fingerprint = fingerprint;
		this.time = time;
	}

	/**
	 * @return the time
	 */
	public Timestamp getTime() {
		return time;
	}

	/**
	 * @return the fingerprint
	 */
	public String getFingerprint() {
		return fingerprint;
	}
	
	/**
	 * Checks whether the fingerprint's timestamp is valid.
	 * 
	 * @return True if the timestamp is valid, false otherwise
	 */
	public boolean isTimestampValid() {
		return time.getTime() + FP_VALIDITY_MS > System.currentTimeMillis();
	}
	
	/**
	 * Two fingerprints are equal if their fingerprint values are equal.
	 * The timestamps are not relevant.
	 * 
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof Fingerprint)) {
			return false;
		}
		return this.fingerprint.equals(((Fingerprint) obj).fingerprint);
	}
}