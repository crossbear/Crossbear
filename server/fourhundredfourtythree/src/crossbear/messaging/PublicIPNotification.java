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
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;

import crossbear.Database;


/**
 * A PublicIPNotification is sent to the client every time it want's to know its PublicIP. The client needs this IP since it will add it as first element to the traces made during Hunting. The trace
 * must contain this IP since this is the IP of the Mitm in the scenario of an poisoned public access point (and others). The server doesn't necessarily observe this IP when the client sends the
 * HuntingTaskReply since it might send it over IPv6 while it hunted using IPv4. Therefore the PublicIP needs to be sent to the client. Moreover it needs to be sent in a way that can't be forged by a
 * malicious client. That's way each PublicIPNotification-message contains a HMAC guaranteeing the authenticity of the PublicIP. Since only the server knows the Key of the HMAC only the server is able
 * to generate it and to use it for authenticity checks.
 * 
 * The structure of the PublicIPNotification-message is
 * - Header
 * - The HMAC for the client's PublicIP address (32 bytes)
 * - The client's PublicIP address (4 or 16 bytes)
 * 
 * Please Note: There are actually two different PublicIPNotification-messages: MESSAGE_TYPE_PUBLIC_IP_NOTIF4 and MESSAGE_TYPE_PUBLIC_IP_NOTIF6. The reason for this is that the decoding becomes more easy when
 * the version of the IP-Address is known as soon as the message's header is read.
 * 
 * @author Thomas Riedmaier
 * 
 */
public class PublicIPNotification extends Message {
	
	// The publicIP for which this Message is generated
	private final InetAddress publicIP;
	
	// The HMAC of publicIP
	private final byte[] hMac;
	
	/**
	 * Create a PublicIPNotification based on a byte[] that was sent by a server and is supposed to be a valid PublicIPNotification-message. The validity is checked within this function.
	 * 
	 * @param raw The byte[] to create the PublicIPNotification from
	 * @param ipVersion The IP-version of the PublicIPNotification-message (4 or 6)
	 * @throws UnknownHostException
	 */
	public PublicIPNotification(byte[] raw, int ipVersion) throws UnknownHostException{
		super((ipVersion == 6)?Message.MESSAGE_TYPE_PUBLIC_IP_NOTIF6:Message.MESSAGE_TYPE_PUBLIC_IP_NOTIF4);
		
		// Make sure that the input - which is supposed to be a PublicIPNotification-message - is long enough
		if (raw.length < 32 + ((ipVersion == 6)?16:4)) {
			throw new IllegalArgumentException("The raw data array is too short: "+ raw.length);
		}
		
		// Cast the Message's HMAC-field into a byte[]
		this.hMac = new byte[32];
		System.arraycopy(raw, 0, this.hMac, 0, 32);
		
		// Extract the IP-address from the byte[]
		byte[] addrBytes = new byte[(ipVersion == 6)?16:4];
		System.arraycopy(raw, 32, addrBytes, 0, addrBytes.length);
		this.publicIP = InetAddress.getByAddress(addrBytes);
	}

	/**
	 * Generate a PublicIPNotification of type MESSAGE_TYPE_PUBLIC_IP_NOTIF6 or MESSAGE_TYPE_PUBLIC_IP_NOTIF4 depending on the version of IP for which it is generated
	 * 
	 * @param publicIP The IP for which this PublicIPNotification is generated
	 * @param db The Database connection to use
	 * @throws SQLException 
	 * @throws NoSuchProviderException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	public PublicIPNotification(InetAddress publicIP, Database db) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SQLException{
		super((publicIP instanceof Inet6Address)?Message.MESSAGE_TYPE_PUBLIC_IP_NOTIF6:Message.MESSAGE_TYPE_PUBLIC_IP_NOTIF4);
		
		this.publicIP = publicIP;

		//Calculate and store the HMAC for the public IP
		this.hMac = HMAC(publicIP.getAddress(),getHmacKey(db));
	}

	/**
	 * @return The HMAC of the IP that is sent within the PublicIPNotification-message
	 */
	public byte[] gethMac() {
		return hMac;
	}
	
	/**
	 * Get the Key that should currently be used to generate HMACs. To do so this function checks if the newest entry in the PublicIPHMacKeys-table is currently valid. If that is the case it is
	 * returned. If not the newest entry and the second newest entry are swapped and the entry that is now in top position is updated with a new validity of 15 minutes and a newly generated Key. Finally this new
	 * key is returned.
	 * 
	 * @param db The Database connection to use
	 * @return The Key that should currently be used to generate HMACs
	 * @throws SQLException
	 */
	private byte[] getHmacKey(Database db) throws SQLException {
		SQLException lastSQLException = null;
		byte[] re;

		/*
		 * "Updating-And-Reading" the key table requires more than one SQL statement. Since the state of the database might change in between the statements transactions are used. Transactions might fail on commit. The only
		 * legal reason for that is that during the process of updating the key table it has been updated by another thread. In that case try getting the newest key and if that succeeded go on. If that failed
		 * again then there is a real problem and an exception is thrown.
		 */
		db.setAutoCommit(false);
		for (int i = 0; i < 2; i++) {
			try {

				// Get the Key that is currently the newest one in the PublicIPHMacKeys-table
				ResultSet latestKey = db.executeQuery("SELECT * FROM PublicIPHMacKeys WHERE Id = 1 LIMIT 1", new Object[]{});

				// Since the table is initially filled there should ALWAYS be a key (if not throw an exception)
				if (!latestKey.next()) {
					throw new SQLException("PublicIPHMacKeys seems to be empty!");
				}

				// When the cache entry is still valid return the entry's key
				Timestamp validUntil = latestKey.getTimestamp("ValidUntil");
				if (validUntil.after(new Timestamp(System.currentTimeMillis()))) {
					re = latestKey.getBytes("Key");

				} else {
					// If not generate a new key ...
					SecureRandom srandom = new SecureRandom();
					re = new byte[64];
					srandom.nextBytes(re);

					// ... and store it in the database
					storeNewHmacKeyInDb(re,db);

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
	 * @return The public IP of the PublicIPNotification-message
	 */
	public InetAddress getPublicIP() {
		return publicIP;
	}
	
	/**
	 * Store a new HMAC-Key in the PublicIPHMacKeys-table with a validity of 15 minutes. To do so the newest entry and the second newest entry in the table are swapped and the entry that is now in top
	 * position is updated with a new validity and a new Key.
	 * 
	 * @param keyBytes The new Key to put at the front position of the PublicIPHMacKeys-table
	 * @param db The Database connection to use
	 * @throws InvalidParameterException
	 * @throws SQLException
	 */
	private void storeNewHmacKeyInDb(byte[] keyBytes, Database db) throws InvalidParameterException, SQLException {

		// Update the second entry in the table with the new key and a validity of 15 minutes
		Object[] params = { keyBytes , new Timestamp(System.currentTimeMillis() + 15*60*1000) };
		db.executeUpdate("UPDATE PublicIPHMacKeys SET Key = ?, ValidUntil = ?  WHERE Id = 2", params);

		// Swap the first two rows so the row with ID 1 will always contain the most current entry
		// The code was created by the use of http://www.microshell.com/database/sql/swap-values-in-2-rows-sql/
		db.executeUpdate("UPDATE  PublicIPHMacKeys  SET key = piphmk.key, validuntil = piphmk.validuntil FROM PublicIPHMacKeys AS piphmk WHERE PublicIPHMacKeys.id <> piphmk.id;", new Object[]{});
		
	}

	/* (non-Javadoc)
	 * @see crossbear.Message#writeContent(java.io.OutputStream)
	 */
	@Override
	protected void writeContent(OutputStream out) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SQLException {
		
		// Write the IP's HMAC
		out.write(hMac);
		
		// Write the IP-Address itself
		out.write(publicIP.getAddress());
		

	}

}
