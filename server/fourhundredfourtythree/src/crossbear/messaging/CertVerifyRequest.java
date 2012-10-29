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

package crossbear.messaging;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import crossbear.CertificateManager;

/**
 * A CertVerifyRequest-message is issued by the client to request the
 * verification of a certificate that it obtained from a server.
 * 
 * The structure of the CertVerifyRequest-message is
 * - Header
 * - Certificate (DER-encoding)
 * - Server that sent the certificate in the format HostName|HostIP|HostPort
 * 
 * The CertVerifyRequest-class stores this message and additionally the IP that sent the request-message and the IP that received the request-message.
 * 
 * @author Thomas Riedmaier
 *
 */
public class CertVerifyRequest extends Message {

    // Regex to validate Hostnames according to RFC 952 and RFC 1123. Additionally it accepts host names containing "_"-characters which seem to be used e.g. by amazonaws.com
    private static final String validHostnameRegex = "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9_\\-]*[a-zA-Z0-9])\\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9_\\-]*[A-Za-z0-9])$";


    /**
     * Read a CertVerifyRequest-message from a InputStream. During the reading a lot of checks on the validity of the supplied data are performed. If one of them fails an exception is thrown.
     * 
     * @param in The InputStream to read the CertVerifyRequest from
     * @param remoteAddr The IP address of the client that sent the CertVerifyRequest
     * @param localAddr The IP of the local interface that received the CertVerifyRequest
     * @return A CertVerifyRequest containing the information read from the InputStream (i.e. the CertVerifyRequest-message) as well as the requesting and the receiving IP.
     * @throws IOException
     * @throws CertificateException
     */
    public static CertVerifyRequest readFromStream(InputStream in, String remoteAddr, String localAddr) throws IOException, CertificateException  {

	// cvr is the CertVerifyRequest that will be returned
	CertVerifyRequest cvr = new CertVerifyRequest();

	// Add the IP that sent the request-message and the IP that received it.
	cvr.setLocalAddr(InetAddress.getByName(localAddr));
	cvr.setRemoteAddr(InetAddress.getByName(remoteAddr));

	// Now Parse the InputStream
	BufferedInputStream bin = new BufferedInputStream(in);

	// First Verify the message is actually of type MESSAGE_TYPE_CERT_VERIFY_REQUEST
	int messageType = bin.read();
	if (messageType != Message.MESSAGE_TYPE_CERT_VERIFY_REQUEST) {
	    throw new IllegalArgumentException("The provided messageType " + messageType + " was not expected");
	}

	// Then read the message length field
	byte[] messageLengthB = new byte[2];
	if(bin.read(messageLengthB, 0, 2) != 2){
	    throw new IOException("Reached unexpected end of stream while extracting message length.");
	}
	int messageLength = Message.byteArrayToInt(messageLengthB);
		
	// Read the options field
	cvr.setOptions( bin.read());
		
	// Cast the Message's Number-Of-Certificates-In-Chain-field into an integer
	int numberOfCertificates = bin.read();
	X509Certificate[] certChain = new X509Certificate[numberOfCertificates];
		
	// Extract the certificate Chain from the InputStream
	CertificateFactory cf = CertificateFactory.getInstance("X.509");
	int certificateChainBytes = 0;
	for (int i = 0; i < numberOfCertificates; i++) {
	    certChain[i] = (X509Certificate) cf.generateCertificate(bin);
	    certificateChainBytes += certChain[i].getEncoded().length;
	}
		
	// Set the certificate chain in the cvr-object
	cvr.setCertChain(certChain);

	// Read the message's remainder. It should be of the format "HostName|HostIP|HostPort". Therefore it can be split into an array of size three.
	String[] host = Message.readNCharsFromStream(bin, messageLength - 5 - certificateChainBytes).split("\\|");

	// Assert that the host-parameter actually consists of three parts.
	if (host.length != 3) {
	    throw new IllegalArgumentException("The host-parameter could not be split in three parts.");
	}

	// The Hostname should match the validHostnameRegex and it's length should be something between 3 and 2042 since this is the maximum of the database "Host" column (therefore "HostPort" has a maximum of 2048)
	if (host[0].length() <= 3 || host[0].length() >= 2042 || !host[0].matches(validHostnameRegex)) {
	    throw new IllegalArgumentException("The provided hostname is not valid: " + host[0]);
	}

	// If the Hostname is valid: store it in the cvr-Object
	cvr.setHostName(host[0]);

	// Check if the second parameter is a valid IP-Address ...
	if(!isValidIPAddress(host[1])){
	    throw new IllegalArgumentException("The provided ip is not valid: " + host[1]);
	}
		
	// ... and if it is: store it in the cvr-Object
	cvr.setHostIP(InetAddress.getByName(host[1])); 

	// Cast the third parameter into a Integer ...
	int port = Integer.valueOf(host[2]);

	// ... and check if it is a valid 16 bit Integer > 0
	if (port <= 0 && port >= (1 << 16)) {
	    throw new IllegalArgumentException("The provided port is outside the valid range: " + port);
	}

	// If it is: store it in the cvr-Object
	cvr.setHostPort(port);

	return cvr;
    }
	
    // The certificate chain that has been sent by the client
    private X509Certificate[] certChain = null;
	
    // The name of the Host from which the certificate has been received
    private String hostName = "";
	
    // The ip of the Host from which the certificate has been received
    private InetAddress hostIP = null;

    // The port of the Host from which the certificate has been received
    private int hostPort = 0;
	
    // The IP that sent the CertVerifyRequest-message
    private InetAddress remoteAddr = null;
	
    // The IP that received the CertVerifyRequest-message
    private InetAddress localAddr = null;
	
    // The options that were chosen by the user (one byte). Currently only the lsb has a meaning: User is behind a ssl-proxy (yes:1; no:0)
    private int options;

    /**
     * Create a new Message of Type MESSAGE_TYPE_CERT_VERIFY_REQUEST
     */
    public CertVerifyRequest()  {
	super(Message.MESSAGE_TYPE_CERT_VERIFY_REQUEST);
    }

    /**
     * @return The certificate chain that has been sent by the client
     */
    public X509Certificate[] getCertChain() {
	return certChain;
    }

    /**
     * Under certain circumstances the client sends duplicate CertVerifyRequest-messages. Therefore CertVerifyResults are cached and resent on duplicate CertVerifyRequest-messages. The KEY of the
     * CertVerifyResultCache-table is the hash of the CertVerifyRequest. This hash is calculated here.
     * 
     * @return The hash of the CertVerifyRequest-Object
     * @throws CertificateEncodingException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */
    public byte[] getHash() throws CertificateEncodingException, IOException, NoSuchAlgorithmException{
		
	ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		
	// Write all elements of the CertVerifyRequest-message to the buffer
	writeContent(buffer);
		
	// Write the remote and local IP-addresses into the buffer
	buffer.write(remoteAddr.getAddress());
	buffer.write(localAddr.getAddress());
		
	// Calculate the SHA256-hash of that buffer and return it
	return CertificateManager.SHA256(buffer.toByteArray());
		
    }
	
    /**
     * @return The IP of the Host from which the certificate has been received
     */
    public InetAddress getHostIP() {
	return hostIP;
    }

    /**
     * @return The name of the Host from which the certificate has been received
     */
    public String getHostName() {
	return hostName;
    }

    /**
     * @return The port of the Host from which the certificate has been received
     */
    public int getHostPort() {
	return hostPort;
    }

    /**
     * @return The IP that received the CertVerifyRequest-message
     */
    public InetAddress getLocalAddr() {
	return localAddr;
    }
	
    /**
     * @return The options that the user chose
     */
    public int getOptions() {
	return options;
    }

    /**
     * @return The IP that sent the CertVerifyRequest-message
     */
    public InetAddress getRemoteAddr() {
	return remoteAddr;
    }
	
    /**
     * @return True if the user claims to be using a SSL-Proxy, false otherwise
     */
    public boolean isUserUsingProxy(){
	return (getOptions()&1) != 0;
    }

    /**
     * @param cert The certificate chain that has been sent by the client
     */
    public void setCertChain(X509Certificate[] certChain) {
	this.certChain = certChain;
    }

    /**
     * @param hostIP The IP of the Host from which the certificate has been received
     */
    public void setHostIP(InetAddress hostIP) {
	this.hostIP = hostIP;
    }

    /**
     * @param hostName The name of the Host from which the certificate has been received
     */
    public void setHostName(String hostName) {
	this.hostName = hostName;
    }

    /**
     * @param hostPort The port of the Host from which the certificate has been received
     */
    public void setHostPort(int hostPort) {
	this.hostPort = hostPort;
    }

    /**
     * @param localAddr The IP that received the CertVerifyRequest-message
     */
    public void setLocalAddr(InetAddress localAddr) {
	this.localAddr = localAddr;
    }
	
    /**
     * @param options The options that were chosen by the user (one byte)
     */
    public void setOptions(int options) {
	this.options = options;
    }

    /**
     * @param remoteAddr The IP that sent the CertVerifyRequest-message
     */
    public void setRemoteAddr(InetAddress remoteAddr) {
	this.remoteAddr = remoteAddr;
    }

    /* (non-Javadoc)
     * @see crossbear.Message#writeContent(java.io.OutputStream)
     */
    @Override
	protected void writeContent(OutputStream out) throws CertificateEncodingException, IOException {

	// First part: The options for the verification process
	out.write(options);	
		
	// Second part: the number of how many certificates are part of the chain
	out.write(this.certChain.length & 255);

	// Third part: the certificate chain (beginning with the server certificate)
	for (int i = 0; i < Math.min(this.certChain.length, 255); i++) {
	    out.write(this.certChain[i].getEncoded());
	}

	// Forth part: The server's Hostname, IP and port
	out.write(new String(hostName + "|" + hostIP.getHostAddress() + "|" + String.valueOf(hostPort)).getBytes());

    }

}
