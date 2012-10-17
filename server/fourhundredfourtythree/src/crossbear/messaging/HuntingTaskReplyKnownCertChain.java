/*
 * Copyright (c) 2011, Thomas Riedmaier, TU MÃ¼nchen
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

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateEncodingException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;

import crossbear.CertificateManager;
import crossbear.Database;

/**
 * A HuntingTaskReplyKnownCertChain-message is one of the two possible messages that could be sent in reply to a HuntingTask. It will be sent in case that the client observed a certificate chain that is already
 * well known by the server.
 * 
 * The structure of the HuntingTaskReplyKnownCertChain-message is
 * - Header
 * - Task ID (4 bytes)
 * - Server time of execution (4 bytes)
 * - HMAC of the PublicIP that was inserted in the trace to the server as first hop(32 bytes)
 * - Hash of the observed certificate chain (32 bytes)
 * - Trace to the server (String of variable length)
 * 
 * @author Thomas Riedmaier
 * 
 */
public class HuntingTaskReplyKnownCertChain extends HuntingTaskReply {

	// The hash of the certificate chain that has been observed by the client
	private byte[] certChainHash;
	
	// ID of the certificate that the Reply claims to have observed
	private Long serverCertID;

	/**
	 * Create a HuntingTaskReplyKnownCertChain based on a byte[] that was sent by a client and is supposed to be a valid HuntingTaskReplyKnownCertChain-message. The validity is checked within this function.
	 * 
	 * @param raw The byte[] to create the HuntingTaskReplyKnownCertChain from (it is supposed to be a valid HuntingTaskReplyKnownCertChain-message)
	 * @param db The Database connection to use
	 * @throws InvalidParameterException
	 * @throws SQLException
	 * @throws InvalidKeyException
	 * @throws UnknownHostException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 */
	public HuntingTaskReplyKnownCertChain(byte[] raw, Database db) throws InvalidParameterException, SQLException, InvalidKeyException, UnknownHostException, NoSuchAlgorithmException, NoSuchProviderException {
		// Create a HuntingTaskReply-Object of Type HuntingTaskReplyKnownCertChain
		super(Message.MESSAGE_TYPE_TASK_REPLY_KNOWN_CERT);

		// Make sure that the input - which is supposed to be a HuntingTaskReplyKnownCertChain-message - is long enough (i.e. at least as long as the fixed length part of a HuntingTaskReplyKnownCertChain-message)
		if (raw.length < 4 + 4 + 32 + 32) {
			throw new IllegalArgumentException("The raw data array is too short: "+ raw.length);
		}

		// Cast the Message's TaskID-field into an integer
		byte[] taskIDBytes = new byte[4];
		System.arraycopy(raw, 0, taskIDBytes, 0, 4);
		taskID = Message.byteArrayToInt(taskIDBytes);

		// Try to load the HuntingTask that belongs to that TaskID (will throw an exception if that Task doesn't exist)
		ResultSet taskDetails = getTaskDetails(taskID,db);

		// In case the task exists but is not active anymore: set taskIsActive to false so storeInDatabse won't do anything
		if (!taskDetails.getBoolean("Active")) {
			taskIsActive = false;
			return;
		}

		// If the task exists AND is active set taskIsActive to true
		taskIsActive = true;

		// Extract the task's details (required to store the observation in the database)
		serverHostPort = taskDetails.getString("TargetHostName") + ":" + taskDetails.getString("TargetPort");
		serverIP = taskDetails.getString("TargetIP");

		// Cast the Message's Server-Time-Of-Execution-field into a Timestamp
		byte[] timestampBytes = new byte[4];
		System.arraycopy(raw, 4, timestampBytes, 0, 4);
		serverTimeOfExecution = new Timestamp(1000 * (long) Message.byteArrayToInt(timestampBytes));

		// Cast the Message's HMAC-field into a byte[]
		pubIPHmac = new byte[32];
		System.arraycopy(raw, 8, pubIPHmac, 0, 32);

		// Cast the Message's cert-chain-Hash-field into a byte[]
		certChainHash = new byte[32];
		System.arraycopy(raw, 40, certChainHash, 0, 32);

		// Cast the Message's Trace-field into a String
		byte[] traceBytes = new byte[raw.length - 72];
		System.arraycopy(raw, 72, traceBytes, 0, traceBytes.length);
		trace = new String(traceBytes);

		/*
		 * Validate the contents of the Message's fields
		 */

		// First: check if the timestamp of the claimed observation is inside a valid range
		validateTimestamp(serverTimeOfExecution);

		// Second: check if the trace is valid
		validateTrace(trace, pubIPHmac, InetAddress.getByName(taskDetails.getString("TargetIP")),db);

		// Third: check if the certificate chain hash is valid:
		validateKnownCertChainHash(certChainHash, serverHostPort,db);

		/*
		 * Perform more checks ( Sourcecode will not be published in order to make attacks on Crossbear harder)
		 */
	}

	/**
	 * Create a new HuntingTaskReplyKnownCertChain-message with explicit content
	 * 
	 * Please note: This function assumes that the input has already been checked for validity and therefore doesn't perform input validation!
	 * 
	 * @param taskID The identifier of this HuntingTask (equals the Id-column in the HuntingTasks-table)
	 * @param serverTimeOfExecution The estimated server local time when the hunting task was executed
	 * @param pubIPHmac The HMAC of the PublicIP that was inserted in the trace to the server as first hop
	 * @param serverCertHash The SHA256-Hash of the observed certificate chain
	 * @param trace The trace to the target
	 */
	public HuntingTaskReplyKnownCertChain(int taskID, Timestamp serverTimeOfExecution, byte[] pubIPHmac, byte[] serverCertHash, String trace){
		// Create a HuntingTaskReply-Object of Type HuntingTaskReplyKnownCertChain
		super(Message.MESSAGE_TYPE_TASK_REPLY_KNOWN_CERT);
		
		this.taskID = taskID;
		this.serverTimeOfExecution = serverTimeOfExecution;
		this.pubIPHmac = pubIPHmac;
		this.certChainHash = serverCertHash;
		this.trace = trace;
	}

	/* (non-Javadoc)
	 * @see crossbear.HuntingTaskReply#storeInDatabase()
	 */
	@Override
	public void storeInDatabase(Database db) throws SQLException, CertificateEncodingException, InvalidParameterException, NoSuchAlgorithmException {
		
		// The HuntingTask might have been deactivated recently. This doesn't throw an exception but replies to those tasks will not be stored in the database anyway.
		if (!taskIsActive)
			return;

		// Store the observation that was made by the client in the database
		long observID = CertificateManager.rememberCertObservation(this.serverCertID, this.serverHostPort, this.serverIP, this.serverTimeOfExecution, "CrossbearHunter", this.observerIP, db);

		// Store the HuntingTaskResult in the database
		CertificateManager.storeHuntingTaskResult(this.taskID, this.trace, observID, db);

	}
	
	/**
	 * Check if the certificate-chain-hash that was sent within the HuntingTaskReplyKnownCertChain-message actually belongs to a certificate chain that is well known for the HuntingTask's HostPort.
	 * 
	 * @param certificateChainHash The certificate-chain-hash to check
	 * @param serverHostPort The Hostname and port of the server from which it has been observed by the client e.g. encrypted.google.com:443
	 * @param db The Database connection to use
	 * @throws InvalidParameterException
	 * @throws SQLException
	 * @throws NoSuchAlgorithmException 
	 * @throws NumberFormatException 
	 */
	private void validateKnownCertChainHash(byte[] certificateChainHash, String serverHostPort, Database db) throws InvalidParameterException, SQLException, NumberFormatException, NoSuchAlgorithmException {
		
		// Calculate the textual representation of the certificateChainHash
		String CCH = byteArrayToHexString(certificateChainHash);
		
		// Try to get the ID of the certificate chain that the client claims to have observed for the scan-target.
		Object[] params = { serverHostPort,CCH };
		ResultSet rs = db.executeQuery("SELECT sc.Id FROM CertObservations AS co JOIN ServerCerts AS sc ON sc.Id = co.CertID WHERE ServerHostPort = ? AND sc.SHA256ChainHash = ? LIMIT 1", params);

		// If there was an entry in the database ... 
		if (rs.next()) {
			
				// ... remember the ID of the certificate that the client observed
				this.serverCertID = Long.valueOf(rs.getString("Id"));
				return;
		}
		
		// If the client sent a forged reply: Throw an exception
		throw new IllegalArgumentException("The certificate chain hash(" + CCH + ") of the reply doesn't belong to a \"well known\" certificate chain");

	}
	
	/* (non-Javadoc)
	 * @see crossbear.Message#writeContent(java.io.OutputStream)
	 */
	@Override
	protected void writeContent(OutputStream out) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, CertificateEncodingException, SQLException {

		// First part of the data: the task id
		out.write(intToByteArray(this.taskID));

		// Second part: the server time when the task was executed
		out.write(intToByteArray((int)(this.serverTimeOfExecution.getTime() / 1000)));

		// Third part: the HMAC of the public IP used for the traceroute (needed by the server to validate the result)
		out.write(this.pubIPHmac);

		// Fourth part: the hash of the observed certificate chain
		out.write(this.certChainHash);

		// Fifth part: the trace to the server
		out.write(this.trace.getBytes());

	}

}
