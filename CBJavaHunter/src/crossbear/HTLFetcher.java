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

package crossbear;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedList;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import crossbear.messaging.CurrentServerTime;
import crossbear.messaging.HuntingTask;
import crossbear.messaging.Message;
import crossbear.messaging.PublicIPNotification;

/**
 * This class provides the functionality to download the HuntingTask-List from the Crossbear server and to transform it into a List of Crossbear Message-Objects.
 * 
 * @author Thomas Riedmaier
 *
 */
public class HTLFetcher {

	
	/**
	 * Extracts one Crossbear of the following Crossbear-Messages from an InputStream:
	 * - MESSAGE_TYPE_PUBLIC_IP_NOTIFX
	 * - MESSAGE_TYPE_CURRENT_SERVER_TIME
	 * - MESSAGE_TYPE_IPVX_SHA256_TASK
	 * 
	 * @param is The InputStream to extract the Messages from
	 * @return A Crossbear-Message-Object representing the next message of the Stream or null if there are no more
	 * @throws IOException
	 */
	private static Message extractNextMessageFromHTL(InputStream is) throws IOException {
		// The first byte of each crossbear.Message is its type
		int messageType = is.read();

		// In case the last message has been read in.read() returned "-1" -> return null
		if (messageType == -1) {
			return null;
		}

		// Verify message type: It has to be either MESSAGE_TYPE_PUBLIC_IP_NOTIFX, MESSAGE_TYPE_CURRENT_SERVER_TIME or MESSAGE_TYPE_IPVX_SHA256_TASK
		if (messageType != Message.MESSAGE_TYPE_PUBLIC_IP_NOTIF4 && messageType != Message.MESSAGE_TYPE_PUBLIC_IP_NOTIF6 && messageType != Message.MESSAGE_TYPE_CURRENT_SERVER_TIME
				&& messageType != Message.MESSAGE_TYPE_IPV4_SHA256_TASK && messageType != Message.MESSAGE_TYPE_IPV6_SHA256_TASK) {
			
			throw new IllegalArgumentException("The provided messageType " + messageType + " was not expected");
		}

		// Read the message's length field (which are bytes 2 & 3 of each crossbear.Message)
		byte[] messageLengthB = Message.readNBytesFromStream(is, 2);
		int messageLength = Message.byteArrayToInt(messageLengthB);

		// Try to read one message from the input (validation is performed inside the message's constructor)
		byte[] raw = Message.readNBytesFromStream(is, messageLength - 3);

		// Build the Message based on the bytes read from the InputStream
		if (messageType == Message.MESSAGE_TYPE_PUBLIC_IP_NOTIF4) {
			return new PublicIPNotification(raw, 4);
		} else if (messageType == Message.MESSAGE_TYPE_PUBLIC_IP_NOTIF6) {
			return new PublicIPNotification(raw, 6);
		} else if (messageType == Message.MESSAGE_TYPE_CURRENT_SERVER_TIME) {
			return new CurrentServerTime(raw);
		} else if (messageType == Message.MESSAGE_TYPE_IPV4_SHA256_TASK) {
			return new HuntingTask(raw, 4);
		} else if (messageType == Message.MESSAGE_TYPE_IPV6_SHA256_TASK) {
			return new HuntingTask(raw, 6);
		} else {
			throw new IllegalArgumentException("The provided messageType " + messageType + " was not expected");
		}
	}

	// The Hostname and port of the Crossbear server (e.g. crossbear.net.in.tum.de:443)
	private String cbServerHostPort;

	// The SHA256-Hash of the certificate that the Crossbear server uses
	private byte[] cbServerCertHash;

	/**
	 * Create a new HuntingTask-List-Fetcher
	 * 
	 * @param cbServerHostPort The Hostname and port of the Crossbear server (e.g. crossbear.net.in.tum.de:443) 
	 * @param cbServerCertHash The SHA256-Hash of the certificate that the Crossbear server uses
	 */
	public HTLFetcher(String cbServerHostPort, byte[] cbServerCertHash) {
		this.cbServerHostPort = cbServerHostPort;
		this.cbServerCertHash = cbServerCertHash;
	}

	/**
	 * Contact the Crossbear server and get the latest HuntingTask-List
	 * 
	 * @return The server's HuntingTask-List as a LinkedList of Crossbear Messages
	 * @throws KeyManagementException
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 */
	public LinkedList<Message> getHTLFromServer() throws KeyManagementException, IOException, NoSuchAlgorithmException {

		// Construct the URL that holds the HuntingTask-List
		URL url = new URL("https://" + cbServerHostPort + "/getHuntingTaskList.jsp");

		// Open a HttpsURLConnection for that url
		HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();

		// Make sure that the Crossbear server uses the certificate it is supposed to use (prevent Mitm-attacks against Crossbear)
		SSLContext sc = SSLContext.getInstance("SSL");
		sc.init(null, new TrustManager[] { new TrustSingleCertificateTM(cbServerCertHash) }, new java.security.SecureRandom());
		conn.setSSLSocketFactory(sc.getSocketFactory());

		// Get the data that the Crossbear Server sends ...
		InputStream is = conn.getInputStream();

		// ... and transform it into a list of Crossbear Messages
		LinkedList<Message> re = new LinkedList<Message>();
		Message m;
		while ((m = extractNextMessageFromHTL(is)) != null) {
			re.add(m);
		}
		
		// Close all opened Streams
		is.close();

		// Return the HuntingTask-List
		return re;
	}
}
