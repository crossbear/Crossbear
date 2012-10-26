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

    Original authors: Thomas Riedmaier, Ralph Holz (TU München, Germany)
*/

package crossbear.messaging;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.LinkedList;

import crossbear.CertificateManager;
import crossbear.Database;

/**
 * A HuntingTaskReplyNewCertChain-message is one of the two possible messages that could be sent in reply to a HuntingTask. It will be sent in case that the client observed a certificate chain that is NOT YET
 * well known by the server.
 * 
 * The structure of the HuntingTaskReplyNewCertChain-message is
 * - Header
 * - Task ID (4 bytes)
 * - Server time of execution (4 bytes)
 * - HMAC of the PublicIP that was inserted in the trace to the server as first hop(32 bytes)
 * - The length of the certificate chain that was observed by the client (1 byte)
 * - The certificate chain observed by the client (byte[] of variable length)
 * - Trace to the target (String of variable length)
 * 
 * @author Thomas Riedmaier
 * 
 */
public class HuntingTaskReplyNewCertChain extends HuntingTaskReply {

    // The CertificateManager that will be used for processing or storing certificates
    private CertificateManager cm = null;
	
    // The certificate chain that was observed by the client
    private X509Certificate[] certChain;

    /**
     * Create a HuntingTaskReplyNewCertChain based on a byte[] that was sent by a client and is supposed to be a valid HuntingTaskReplyNewCertChain-message. The validity is checked within this function.
     * 
     * @param raw The byte[] to create the HuntingTaskReplyNewCertChain from (it is supposed to be a valid HuntingTaskReplyNewCertChain-message)
     * @param cm The CertificateManager that will be used for processing or storing certificates
     * @param db The Database connection to use
     * @throws CertificateException
     * @throws InvalidParameterException
     * @throws SQLException
     * @throws IOException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidAlgorithmParameterException
     * @throws KeyStoreException
     */
    public HuntingTaskReplyNewCertChain(byte[] raw, CertificateManager cm, Database db) throws CertificateException, InvalidParameterException, SQLException, IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, KeyStoreException {
	// Create a HuntingTaskReply-Object of Type HuntingTaskReplyNewCertChain
	super(Message.MESSAGE_TYPE_TASK_REPLY_NEW_CERT);
		
	// Store a handle to the CertificateManager so the certificate Chain can be processed and stored
	this.cm = cm;

	// Make sure that the input - which is supposed to be a HuntingTaskReplyNewCertChain-message - is long enough (i.e. at least as long as the fixed length part of a HuntingTaskReplyNewCertChain-message)
	if (raw.length < 4 + 4 + 32 + 1 + 32) {
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

	// Cast the Message's Number-Of-Certificates-In-Chain-field into an integer
	int numberOfCertificates = (0xFF & (int) raw[40]);
	certChain = new X509Certificate[numberOfCertificates];

	// Cast the remaining Message into a BufferedInputStream so the certificate chain can easily be extracted
	byte[] remainingMessage = new byte[raw.length - 41];
	System.arraycopy(raw, 41, remainingMessage, 0, remainingMessage.length);
	BufferedInputStream remainingMessageIS = new BufferedInputStream(new ByteArrayInputStream(remainingMessage));
		
	// Extract the certificate Chain
	CertificateFactory cf = CertificateFactory.getInstance("X.509");
	for (int i = 0; i < numberOfCertificates; i++) {
	    certChain[i] = (X509Certificate) cf.generateCertificate(remainingMessageIS);
	}

	// Cast the Message's Trace-field into a String
	trace = Message.inputStreamToString(remainingMessageIS);

	/*
	 * Validate the contents of the Message's fields
	 */

	// First: check if the timestamp of the claimed observation is inside a valid range
	validateTimestamp(serverTimeOfExecution);

	// Second: check if the trace is valid
	validateTrace(trace, pubIPHmac, InetAddress.getByName(taskDetails.getString("TargetIP")),db);

	// Third: check if the certificate chain is valid within itself (i.e. can it be ordered in a way that it is sane?)
	LinkedList<X509Certificate> validatedChain = cm.makeCertChainValid(certChain,50,false);
	if (validatedChain == null) {
	    throw new IllegalArgumentException("The certificate chain could not be validated!");
	} else{
	    // The chain might have been transmitted in a wrong order. Since validatedChain is in the correct order -> Store it instead of certChain.
	    certChain = validatedChain.toArray(new X509Certificate[]{});
	}
		
	/*
	 * Perform more checks ( Sourcecode will not be published in order to make attacks on Crossbear harder)
	 */
    }

    /**
     * Create a new HuntingTaskReplyNewCertChain-message with explicit content
     * 
     * Please note: This function assumes that the input has already been checked for validity and therefore doesn't perform input validation!
     * Please note: This constructor DOES NOT SET the CertificateManager so storeInDatabase MUST NOT BE CALLED ON THIS OBJECT!
     * 
     * @param taskID The HuntingTask's ID for which this reply is sent
     * @param serverTimeOfExecution The estimated server local time when the hunting task was executed
     * @param pubIPHmac The HMAC of the PublicIP that was inserted in the trace to the server as first hop
     * @param certChain The certificate chain observed by the client
     * @param trace The trace to the target
     */
    public HuntingTaskReplyNewCertChain(int taskID, Timestamp serverTimeOfExecution, byte[] pubIPHmac, X509Certificate[] certChain, String trace){
	// Create a HuntingTaskReply-Object of Type HuntingTaskReplyNewCertChain
	super(Message.MESSAGE_TYPE_TASK_REPLY_NEW_CERT);
		
	this.taskID = taskID;
	this.serverTimeOfExecution = serverTimeOfExecution;
	this.pubIPHmac = pubIPHmac;
	this.certChain = certChain;
	this.trace = trace;
    }
	
    /* (non-Javadoc)
     * @see crossbear.HuntingTaskReply#storeInDatabase()
     */
    @Override
	public void storeInDatabase(Database db) throws InvalidAlgorithmParameterException, KeyStoreException, NoSuchAlgorithmException, CertificateException, UnsupportedEncodingException, NoSuchProviderException, SQLException {

	// The HuntingTask might have been deactivated recently. This doesn't throw an exception but replies to those tasks will not be stored in the database anyway.
	if (!taskIsActive)
	    return;

	// Store the newly observed chain in the database
	Long serverCertID = cm.storeCertChain(this.certChain, db);

	// Store the observation that was made by the client in the database
	long observID = CertificateManager.rememberCertObservation(serverCertID, this.serverHostPort, this.serverIP, this.serverTimeOfExecution, "CrossbearHunter", observerIP, db);

	// Store the HuntingTaskResult in the database
	CertificateManager.storeHuntingTaskResult(this.taskID, this.trace, observID, db);

    }

    /* (non-Javadoc)
     * @see crossbear.Message#writeContent(java.io.OutputStream)
     */
    @Override
	protected void writeContent(OutputStream out) throws MessageSerializationException {

	// First part of the data: the task id
	try {
	    out.write(intToByteArray(this.taskID));
	}
	catch (IOException e) {
	    throw new MessageSerializationException("Error serializing task ID.", e);
	}

	// Second part: the server time when the task was executed
	try {
	    out.write(intToByteArray((int)(this.serverTimeOfExecution.getTime() / 1000)));
	}
	catch (IOException e) {
	    throw new MessageSerializationException("Error serializing server time.", e);
	}

	// Third part: the HMAC of the public IP used for the traceroute (needed by the server to validate the result)
	try {
	    out.write(this.pubIPHmac);
	}
	catch (IOException e) {
	    throw new MessageSerializationException("Error serializing public IP HMAC.", e);
	}

	// Fourth part: the number of how many certificates are part of the chain
	try {
	    out.write(this.certChain.length & 255);
	}
	catch (IOException e) {
	    throw new MessageSerializationException("Error serializing number of certificates in chain.", e);
	}

	// Fifth part: the certificate chain (beginning with the server certificate)
	for (int i = 0; i < Math.min(this.certChain.length, 255); i++) {
	    try {
		out.write(this.certChain[i].getEncoded());
	    }
	    catch (IOException e) {
		throw new MessageSerializationException("Error serializing certificate.", e);
	    }
	    catch (CertificateEncodingException e) {
		throw new MessageSerializationException("Error serializing certificate (encoding seems to be wrong).", e);
	    }
	}

	// Sixth part: the trace to the server
	try {
	    out.write(this.trace.getBytes());
	}
	catch (IOException e) {
	    throw new MessageSerializationException("Error serializing trace to server.", e);
	}

    }

}
