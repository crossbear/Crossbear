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

import java.io.IOException;
import java.io.OutputStream;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.InvalidParameterException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Vector;

import crossbear.Database;

/**
 * HuntingTask-messages are sent from the Crossbear server to the Crossbear client(s). Upon receiving a HuntingTask-message a client will contact the scan-target and download its certificate chain.
 * Also it will run a traceroute on the scan-target. After that it will check if the certificate it received is already well known to the server. Depending on the result of this check the client will
 * either generate a HuntingTaskReplyKnownCert-message or a HuntingTaskReplyNewCert-message and send it to the server.
 * 
 * The structure of the HuntingTask-message is
 * - Header
 * - TaskID (four bytes) 
 * - Number of certificates that are already well known (1 byte)
 * - Array of SHA256-hashes of the certificates that are already well known 
 * - IP Address of the scan-target in binary format (4 or 16 bytes)
 * - Port of the scan-target (two bytes) 
 * - Hostname of the scan-target (String of variable length)
 * 
 * Please Note: There are actually two different HuntingTask-messages: MESSAGE_TYPE_IPV6_SHA256_TASK and MESSAGE_TYPE_IPV4_SHA256_TASK. The reason for this is that the decoding becomes more easy when
 * the version of the IP-Address is known as soon as the message's header is read.
 * 
 * @author Thomas Riedmaier
 * 
 */
public class HuntingTask extends Message {

	/**
	 * Get all HuntingTasks from the HuntingTasks-table that are currently active
	 * 
	 * @param db The Database connection to use
	 * @return A Vector that contains all currently active HuntingTasks
	 * @throws UnknownHostException
	 * @throws SQLException
	 */
	public static Vector<HuntingTask> getAllActive(Database db) throws UnknownHostException, SQLException {
		
		// Create a empty result vector
		Vector<HuntingTask> re = new Vector<HuntingTask>();
		
		// Query the Database for all currently active HuntingTasks
		Object[] params = {  };
		ResultSet rs = db.executeQuery("SELECT * FROM HuntingTasks WHERE Active = 'true'", params);
		
		// Iterate through all entries of the result of the database query and add them to the result vector.
		while(rs.next()){
			re.add(new HuntingTask(rs.getInt("Id"),rs.getString("TargetHostName"),InetAddress.getByName(rs.getString("TargetIP")),rs.getInt("TargetPort"),db));
		}
		
		// Return the result
		return re;
	}

	// The identifier of this HuntingTask (equals the Id-column in the HuntingTasks-table)
	private final int taskID;
	
	// The scan-target's IP
	private final InetAddress targetIP;
	
	// The scan-target's Port (there is no such thing as unsigned short in Java)
	private final int targetPort;
	
	// The scan-target's Hostname
	private final String targetHostName;

	// An array of byte[]s representing the hashes of the certificates that are already well known for the HuntingTask
	private final byte[][] alreadyKnownCertHashes;
	
	
	/**
	 * Create a HuntingTask based on a byte[] that was sent by a server and is supposed to be a valid HuntingTask-message. The validity is checked within this function.
	 * 
	 * @param raw The byte[] to create the HuntingTask from
	 * @param ipVersion The IP-version of the HuntingTask-message (4 or 6)
	 * @throws UnknownHostException
	 */
	public HuntingTask(byte[] raw, int ipVersion) throws UnknownHostException {
		super((ipVersion == 6) ? Message.MESSAGE_TYPE_IPV6_SHA256_TASK : Message.MESSAGE_TYPE_IPV4_SHA256_TASK);
		
		// Make sure that the input - which is supposed to be a HuntingTask-message - is long enough (i.e. at least as long as the fixed length part of a HuntingTask-message)
		if (raw.length < 4 + 1 + 2 + ((ipVersion == 6)?16:4)) {
			throw new IllegalArgumentException("The raw data array is too short: "+ raw.length);
		}
		
		// The number of the bytes in "raw" that have already been read and processed
		int bytesRead = 0;

		// Cast the Message's TaskID-field into an integer
		byte[] taskIDBytes = new byte[4];
		System.arraycopy(raw, bytesRead, taskIDBytes, 0, 4);
		taskID = Message.byteArrayToInt(taskIDBytes);
		bytesRead += 4;
		
		// Extract the number of well known certificate hashes
		int numOfKnownCerts = (0xFF & (int)raw[4]);
		bytesRead +=1;
		
		// Create an byte[][] big enough to hold all known hashes
		alreadyKnownCertHashes = new byte[numOfKnownCerts][32];
		
		// Read all known hashes and store them in alreadyKnownCertHashes
		for(int i = 0 ; i< numOfKnownCerts;i++){
			System.arraycopy(raw, bytesRead, alreadyKnownCertHashes[i], 0, 32);
			bytesRead += 32;
		}
		
		// Extract the IP-address of the HuntingTask's target
		byte[] addrBytes = new byte[(ipVersion == 6)?16:4];
		System.arraycopy(raw, bytesRead, addrBytes, 0, addrBytes.length);
		targetIP = InetAddress.getByAddress(addrBytes);
		bytesRead += addrBytes.length;
		
		// Extract the Port of the HuntingTask's target
		byte[] portBytes = new byte[2];
		System.arraycopy(raw, bytesRead, portBytes, 0, 2);
		targetPort = byteArrayToInt(portBytes);
		bytesRead +=2;
			
		// Cast the Message's Hostname-field into a String
		byte[] hostnameBytes = new byte[raw.length - bytesRead];
		System.arraycopy(raw, bytesRead, hostnameBytes, 0, hostnameBytes.length);
		targetHostName = new String(hostnameBytes);
	}

	/**
	 * Create a HuntingTask-Object representation of an entry in the HuntingTasks-table.
	 * 
	 * Please Note: This constructor is only meant to be used by functions that are accessing the HuntingTasks-table in a read-only way.
	 * 
	 * @param taskID The value of the "Id"-field
	 * @param targetHostName The value of the "TargetHostName"-field
	 * @param targetIP The value of the "TargetIP"-field
	 * @param targetPort The value of the "TargetPort"-field
	 * @param db The Database connection to use for further operations
	 * @throws SQLException 
	 */
	private HuntingTask(int taskID, String targetHostName, InetAddress targetIP, int targetPort, Database db) throws SQLException {
		super((targetIP instanceof Inet6Address) ? Message.MESSAGE_TYPE_IPV6_SHA256_TASK : Message.MESSAGE_TYPE_IPV4_SHA256_TASK);
		
		this.targetHostName = targetHostName;
		this.targetIP = targetIP;
		this.targetPort = targetPort;
		this.taskID = taskID;
		
		// Calculate and store the hashes of the well known certificates for this HuntingTask
		// SUGG: remember that this is exploitable: you can get many (all?) hashes of certs from our DB and then compare it is currently limited to a limited number of hash values (3), which is good 
		this.alreadyKnownCertHashes = calculateAlreadyKnownCertHashes(3, db);
	}

	/**
	 * Get the scan-target's HuntingTask from the HuntingTask-table. If there is no active HuntingTask for it: create it first.
	 * 
	 * Please note: This function assumes that the input has already been checked for validity (e.g. hostname not too long, IP not null, etc ...)
	 * 
	 * @param targetHostName The Hostname of the scan-target
	 * @param targetIP The IP of the scan-target
	 * @param targetPort The port of the scan-target
	 * @param db The Database connection to use for further operations
	 * @throws SQLException
	 */
	public HuntingTask(String targetHostName, InetAddress targetIP, int targetPort, Database db) throws SQLException {
		super((targetIP instanceof Inet6Address) ? Message.MESSAGE_TYPE_IPV6_SHA256_TASK : Message.MESSAGE_TYPE_IPV4_SHA256_TASK);


		this.targetHostName = targetHostName;
		this.targetIP = targetIP;
		this.targetPort = targetPort;

		// Get the TaskID for this HuntingTask (and if there is no active HuntingTask for this scan-target create a database entry for it)
		int taskID = getExistingTaskID(db);
		if (-1 != taskID) {
			this.taskID = taskID;
		} else {
			this.taskID = createNewTask(db);
		}


		// Calculate and store the hashes of the well known certificates for this HuntingTask
		this.alreadyKnownCertHashes = calculateAlreadyKnownCertHashes(3, db);
	}

	/**
	 * Get the SHA256Hashes of all well known certificates for this HuntingTask. A certificate is well known for a hunting task if it has been observed for the HuntingTask's scan-target and if its certificate-chain is known.
	 * 
	 * @param max The maximum number of hashes to be returned.
	 * @param db The Database connection to use
	 * @return An array of SHA256Hashes - one for each well known certificate for the current HuntingTask (limited by the "max" parameter)
	 * @throws SQLException
	 */
	private byte[][] calculateAlreadyKnownCertHashes(int max, Database db) throws SQLException {

		// Create a empty result vector
		Vector<byte[]> re = new Vector<byte[]>();

		// Get the SHA256-hashes of all certificates that have ever been observed for the scan-target and whose certificate-chains are known. Order them by their most recent observation.
		Object[] params = { targetHostName + ":" + String.valueOf(targetPort) };
		ResultSet rs = db.executeQuery("SELECT co.CertID, Max(co.TimeOfObservation) as LastSeen FROM CertObservations AS co JOIN ServerCerts AS sc ON sc.SHA256DERHash = co.CertID WHERE ServerHostPort = ? AND sc.CertChainMD5 IS NOT NULL GROUP BY co.CertID ORDER BY LastSeen DESC", params);

		// Store up to "max" hashes in the result vector
		for (int i = 0; i < max; i++) {
			if (!rs.next()) {
				break;
			}

			// Since the databse stores the HexString-representation of the SHA256-hashees they need to be converted into their byte[]-representation
			re.add(hexStringToByteArray(rs.getString("CertID")));
		}

		// Return the result as an array
		return re.toArray(new byte[][] {});
	}

	/**
	 * Create a new entry in the HuntingTasks-table representing the current HuntingTask.
	 * 
	 * @param db The Database connection to use
	 * @return The ID of the newly created HuntingTask
	 * @throws InvalidParameterException
	 * @throws SQLException
	 */
	private int createNewTask(Database db) throws InvalidParameterException, SQLException {
		Object[] params = { targetHostName, targetIP, targetPort,new Timestamp(System.currentTimeMillis()) };
		String key = db.executeInsert("INSERT INTO HuntingTasks (TargetHostName, TargetIP, TargetPort, TimeOfCreation, Active) VALUES (?,?,?,?, 'true')", params);

		return Integer.valueOf(key);
	}

	/**
	 * @return The Hashes of the certificates that are well known for the HuntingTask
	 */
	public byte[][] getAlreadyKnownCertHashes() {
		return alreadyKnownCertHashes;
	}

	/**
	 * Assume that a HuntingTask exists that has the same properties like the ones that are stored within the current object. If this assumption is true this function will return the ID of that
	 * HuntingTask and -1 if the assumption is wrong.
	 * 
	 * @param db The Database connection to use
	 * @return The ID of the HuntingTask having the same properties of the current object or -1 if there is none.
	 * @throws SQLException
	 */
	private int getExistingTaskID(Database db) throws SQLException  {

		Object[] params = { targetHostName, targetIP, targetPort };
		ResultSet rs = db.executeQuery("SELECT Id FROM HuntingTasks WHERE TargetHostName = ? AND TargetIP = ? AND TargetPort = ? AND Active = 'true' ORDER BY Id DESC LIMIT 1", params);

		if (rs.next()) {
			return rs.getInt("Id");
		} else {
			return -1;
		}

	}

	/**
	 * @return The scan-target's Hostname
	 */
	public String getTargetHostName() {
		return targetHostName;
	}

	/**
	 * @return The scan-target's IP
	 */
	public InetAddress getTargetIP() {
		return targetIP;
	}

	/**
	 * @return The scan-target's Port
	 */
	public int getTargetPort() {
		return targetPort;
	}

	/**
	 * @return The ID of this HuntingTask
	 */
	public int getTaskID() {
		return taskID;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see crossbear.Message#writeContent(java.io.OutputStream)
	 */
	@Override
	protected void writeContent(OutputStream out) throws IOException, SQLException {

		// Write the taskID (four bytes integer)
		out.write(Message.intToByteArray(taskID));

		// Write the number of how many certificates are well known for the HuntingTask (one byte)
		out.write((byte) alreadyKnownCertHashes.length);

		// Write the hashes of the well known certificates (32 bytes each)
		for (int i = 0; i < (byte) alreadyKnownCertHashes.length; i++) {
			out.write(alreadyKnownCertHashes[i]);
		}

		// Write the scan-target's IP-Address (16 or 4 bytes depending on the IP-version)
		out.write(targetIP.getAddress());

		// Write the scan-target's port (2 bytes integer)
		out.write(Message.intToByteArray(targetPort), 2, 2);

		// Write the scan-target's Hostname
		out.write(targetHostName.getBytes());

	}

}
