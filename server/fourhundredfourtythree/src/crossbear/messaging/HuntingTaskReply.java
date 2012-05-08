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

package crossbear.messaging;

import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Vector;

import crossbear.Database;

/**
 * HuntingTaskReplies are sent by the Crossbear clients in reply to a HuntingTask. There are two different HuntingTaskReplies: The HuntingTaskReplyKnownCertChain and the HuntingTaskReplyNewCertChain. There is
 * quite a lot of functionality which they need both. This code is moved into this class:
 * - validation of Timestamps
 * - validation of Traces
 * - loading of the HuntingTask-details from the database
 * 
 * Additionally this class is created to give both subclasses a common interface.
 * 
 * @author Thomas Riedmaier
 * 
 */
public abstract class HuntingTaskReply extends Message {

	/**
	 * Each HuntingTaskReply contains a Timestamp representing the time during which the HuntingTask was executed by the client. This Timestamp is not recorded according to the client's local clock
	 * but according to the server's clock. Therefore it should be not too far in the past and not in the future. If one of these constraints is not true this function throws an exception.
	 * 
	 * @param ts  The Timestamp to check
	 */
	protected static void validateTimestamp(Timestamp ts) {

		// Don't accept replies if their timestamps are older than 30 minutes
		if (ts.before(new Timestamp(System.currentTimeMillis() - 1000 * 60 * 30))) {
			throw new IllegalArgumentException("HuntingTaskReply is too old according to its timestamp (" + ts + ")");
		}

		// Don't accept replies if their timestamps are in the future (by more than 10 seconds)
		if (ts.after(new Timestamp(System.currentTimeMillis() + 10 * 1000))) {
			throw new IllegalArgumentException("HuntingTaskReply was measured in the future according to its timestamp (" + ts + ")");
		}

	}
	
	// Data extracted from the Reply
	protected int taskID;
	protected Timestamp serverTimeOfExecution;
	protected byte[] pubIPHmac;
	protected String trace;
	
	// Data necessary to create the database entries
	protected String serverHostPort;
	protected String serverIP;
	protected String observerIP;

	// Flag whether the HuntingTask-Reply belongs to an active or an inactive task.
	protected boolean taskIsActive;

	/**
	 * Create a new HuntingTaskReply
	 * 
	 * @param type The message-type of the HuntingTaskReply (MESSAGE_TYPE_TASK_REPLY_NEW_CERT or MESSAGE_TYPE_TASK_REPLY_KNOWN_CERT)
	 */
	protected HuntingTaskReply(byte type) {
		super(type);
	}

	/**
	 * Get all Keys from the PublicIPHMacKeys-table that were used to create HMACs for PublicIPs during the last 30 minutes.
	 * 
	 * @param db The Database connection to use
	 * @return An array of all keys that were used to create HMACs for PublicIPs during the last 30 minutes
	 * @throws SQLException
	 */
	private byte[][] getPublicIPHMacKeys(Database db) throws SQLException {

		// Create a empty result vector
		Vector<byte[]> re = new Vector<byte[]>();

		// Query the PublicIPHMacKeys-table for all Keys that very used during the last 30 minutes
		Object[] params = { new Timestamp(System.currentTimeMillis() - 30 * 60 * 1000) };
		ResultSet rs = db.executeQuery("SELECT Key FROM PublicIPHMacKeys WHERE ValidUntil > ?", params);

		// Iterate over all results returned from the database
		while (rs.next()) {
			
			// For each result: Read the "Key"-field ...
			byte[] key = rs.getBytes("Key");

			// ... and add it to the result-vector
			if (key != null) {
				re.add(key);
			}
		}

		// Convert the result into an array and return it
		return re.toArray(new byte[][]{});

	}

	/**
	 * Query the database for a entry in the HuntingTasks-table with a certain taskID
	 * 
	 * @param taskID The ID to look for
	 * @param db The Database connection to use
	 * @return The result returned by the database (if non exists an exception is thrown)
	 * @throws InvalidParameterException
	 * @throws SQLException
	 */
	protected ResultSet getTaskDetails(int taskID, Database db) throws InvalidParameterException, SQLException {

		Object[] params = { taskID };
		ResultSet rs = db.executeQuery("SELECT * FROM HuntingTasks WHERE Id = ?", params);
		
		if (!rs.next()) {
			throw new IllegalArgumentException("The task with ID "+taskID+" does not exist!");
		}

		return rs;
	}

	/**
	 * After a HuntingTaskReply was successfully created without an exception being thrown it is ready to be inserted into the database. This function does exactly that.
	 * 
	 * @param The Database Connection to use for storing the data
	 * @throws InvalidAlgorithmParameterException
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws UnsupportedEncodingException
	 * @throws NoSuchProviderException
	 * @throws SQLException
	 */
	public abstract void storeInDatabase(Database db) throws InvalidAlgorithmParameterException, KeyStoreException, NoSuchAlgorithmException, CertificateException, UnsupportedEncodingException, NoSuchProviderException, SQLException;

	/**
	 * Each HuntingTaskReply contains the result of the traceroute that the client executed for the scan-target. This result has to fulfill several constraints:
	 * - The trace must consist of valid IP-addresses only!
	 * - The HMAC that was sent within the HuntingTaskReply must match the first entry of the trace (this ensures that the first entry of the trace is not forged and therefore equal to the client's PublicIP)!
	 * - The scan-target's IP must match the last entry of the trace!
	 * 
	 * This function checks each of these constraints and throws an exception if any of them is violated.
	 * 
	 * @param trace The Trace to check
	 * @param hMac The HMAC that should match the first entry of the trace
	 * @param serverIP The scan-target's IP
	 * @param db The Database connection to use
	 * @throws UnknownHostException
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws SQLException
	 */
	protected void validateTrace(String trace, byte[] hMac, InetAddress serverIP, Database db) throws UnknownHostException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SQLException {

		// Split the trace into its parts
		String[] traceParts = trace.split("[\\n\\|]");

		// Check if all parts of the traceroute are actually valid IPs
		for (int i = 0; i < traceParts.length; i++) {
			if (!isValidIPAddress(traceParts[i])) {
				throw new IllegalArgumentException("The trace("+trace+") does not strictly consist of IP-Addresses: " + traceParts[i]);
			}
		}

		// Check if the end of the trace matches the scan target
		if (!serverIP.equals(InetAddress.getByName(traceParts[traceParts.length - 1]))) {
			throw new IllegalArgumentException("The reply's trace("+trace+") doesn't lead to the scan target: "+ traceParts[traceParts.length - 1] + " instead of "+serverIP.getHostAddress());
		}
		
		// Transform the first IP of the Trace into its byte[]-representation
		byte[] lastIPBytes = InetAddress.getByName(traceParts[0]).getAddress();
		
		// Get all keys that were used to create HMACs during the last 30 minutes
		byte[][] hMacKeys = getPublicIPHMacKeys(db);
		
		/*
		 * Check if one of these keys can be used to create the HMAC sent within the HuntingTaskReply when inserted into HMAC(firstEntryOfTrace). This would prove that the first entry of the trace is
		 * equal to an publicIP that the client had access to during the last 30 minutes.
		 */
		boolean hMacMatches = false;
		for (int i = 0; i < hMacKeys.length; i++) {

			if (Arrays.equals(HMAC(lastIPBytes, hMacKeys[i]), hMac)) {
				hMacMatches = true;
				break;
			}

		}

		// If that is not the case the trace is most likely forged and should therefore be rejected
		if (!hMacMatches) {
			throw new IllegalArgumentException("The hMac that was sent within the message doesn't match the trace("+trace+")!");
		}
		
		// If the trace passed all of the tests above it is assumed that the first entry of the trace is equal to the IP that actually executed the HuntingTask
		this.observerIP = traceParts[0];

	}

}
