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

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.net.MalformedURLException;
import java.util.LinkedList;
import java.util.logging.Logger;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import crossbear.messaging.CurrentServerTime;
import crossbear.messaging.HuntingTask;
import crossbear.messaging.Message;
import crossbear.messaging.PublicIPNotification;
import crossbear.messaging.MalformedMessageException;

/**
 * This class provides the functionality to download the HuntingTask-List from the Crossbear server and to transform it into a List of Crossbear Message-Objects.
 * 
 * @author Thomas Riedmaier
 *
 */
public class HTLFetcher {

    // the logger
    Logger logger = null;

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
	logger = Logger.getLogger("JavaHunter");
	
	this.cbServerHostPort = cbServerHostPort;
	this.cbServerCertHash = cbServerCertHash;
	
	logger.info("HTLFetcher up and running.");
    }

    
    /**
     * Extracts one of the following Crossbear-Messages from an InputStream:
     * - MESSAGE_TYPE_PUBLIC_IP_NOTIFX
     * - MESSAGE_TYPE_CURRENT_SERVER_TIME
     * - MESSAGE_TYPE_IPVX_SHA256_TASK
     * 
     * @param is The InputStream to extract the Messages from
     * @return A Crossbear-Message-Object representing the next message of the Stream or null if there are no more
     * @throws MalformedMessageException
     * @throws IOException
     */
    private static Message extractNextMessageFromHTL(InputStream is) throws MalformedMessageException, IOException {
	// The first byte of each crossbear.Message is its type
	int messageType = is.read();
	
	// In case the last message has been read in.read() returned "-1" -> return null
	if (messageType == -1) {
	    return null;
	}
	
	// Verify message type: It has to be either MESSAGE_TYPE_PUBLIC_IP_NOTIF4, MESSAGE_TYPE_PUBLIC_IP_NOTIF6, MESSAGE_TYPE_CURRENT_SERVER_TIME, MESSAGE_TYPE_IPV4_SHA256_TASK, or MESSAGE_TYPE_IPV6_SHA256_TASK
	if (messageType != Message.MESSAGE_TYPE_PUBLIC_IP_NOTIF4 && messageType != Message.MESSAGE_TYPE_PUBLIC_IP_NOTIF6 && messageType != Message.MESSAGE_TYPE_CURRENT_SERVER_TIME
	    && messageType != Message.MESSAGE_TYPE_IPV4_SHA256_TASK && messageType != Message.MESSAGE_TYPE_IPV6_SHA256_TASK) {
	    throw new MalformedMessageException("The provided message type " + messageType + " is not a valid message type.");
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
	} else return new HuntingTask(raw, 6);
    }
    


    /**
     * Contact the Crossbear server and get the latest HuntingTask-List
     * 
     * @return The server's HuntingTask-List as a LinkedList of Crossbear Messages
     * @throws KeyManagementException
     * @throws MalformedURLException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws MalformedMessageException
     */
    public LinkedList<Message> getHTLFromServer() throws KeyManagementException, MalformedURLException, IOException, NoSuchAlgorithmException, MalformedMessageException {
	
	// Construct the URL that holds the HuntingTask-List
	URL url = new URL("https://" + cbServerHostPort + "/getHuntingTaskList.jsp");
	
	// Open a HttpsURLConnection for that url
	logger.info("Trying to establish connection to Crossbear server to retrieve hunting task list.");
	HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
	
	// Make sure that the Crossbear server uses the certificate it is supposed to use (prevent Mitm-attacks against Crossbear)
	SSLContext sc = SSLContext.getInstance("SSL");
	sc.init(null, new TrustManager[] { new TrustSingleCertificateTM(cbServerCertHash) }, new java.security.SecureRandom());
	conn.setSSLSocketFactory(sc.getSocketFactory());
	
	// Get the data that the Crossbear Server sends ...
	InputStream is = conn.getInputStream();
	
	// ... and transform it into a list of Crossbear Messages
	//
	// Note that a MalformedMessageException is intentionally
	// thrown on - the JavaHunter is not supposed to continue
	// processing messages in such a case but stop.
	LinkedList<Message> re = new LinkedList<Message>();
	Message m;
	while ((m = extractNextMessageFromHTL(is)) != null) {
	    re.add(m);
	}

	if (re.size() == 0) {
	    logger.warning("Received empty list of Crossbear messages.");
	}
	
	// Close all opened Streams
	is.close();
	
	// Return the HuntingTask-List
	logger.info("Retrieved hunting task list.");
	return re;
    }
}