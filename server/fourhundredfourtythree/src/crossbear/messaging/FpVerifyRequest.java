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

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

import crossbear.Ssh.KeyType;


/**
 * An FpVerifyRequest message is issued by the client to request the verification of a SSH host key fingerprint that it obtained from a server. 
 * 
 * The structure of the CertVerifyRequest-message is
 * - Header
 * - Message format version (1 byte)
 * - IPv4 address of queried host (4 bytes)
 * - Port number of queried host (2 bytes)
 * - Key type of queried host (1 byte)
 * - NID of ECDSA key (2 bytes)
 * - Fingerprint of queried host (variable length)
 * 
 * The FpVerifyRequest class stores this message and additionally the IP that sent the request-message and the IP that received the request-message.
 * 
 * @author Thomas Riedmaier
 * @author Oliver Gasser
 *
 */
public class FpVerifyRequest extends Message {
	
	/////////////////////////////////////////////////
	// MESSAGE_TYPE_FP_VERIFY_REQUEST format:      //
	/////////////////////////////////////////////////
	// | T | L | V | IP | P | K | N |   FP ...   | //
	/////////////////////////////////////////////////
	// T  = Message type (1 Byte) = 50             //
	// L  = Message length in bytes (2 Bytes)      //
	// V  = Message format version (1 Byte) = 1    //
	// IP = IPv4 address of queried host (4 Bytes) //
	// P  = Port number of queried host (2 Bytes)  //
	// K  = Keytype of queried host (1 Byte)       //
	// N  = NID of ECDSA key (2 Bytes)
	// FP = Fingerprint of queried host (variable) //
	/////////////////////////////////////////////////
		
	// The format version of the FpVerifyRequest message
	private static final byte MESSAGE_TYPE_FP_VERIFY_REQUEST_FORMAT_VERSION = 1;
	
	// The IP of the Host from which the certificate has been received
	private InetAddress hostIP = null;

	// The port of the Host from which the certificate has been received
	private int hostPort = 0;
	
	// The IP that sent the CertVerifyRequest-message
	private InetAddress remoteAddr = null;
	
	// The IP that received the CertVerifyRequest-message
	private InetAddress localAddr = null;
	
	// The key type corresponding to the fingerprint to be verified
	private KeyType keyType;
	
	// The NID for ECDSA keys
	private int keyNid;
	
	// The key's fingerprint
	private String fingerprint;

	/**
	 * Create a new Message of Type MESSAGE_TYPE_FP_VERIFY_REQUEST
	 */
	public FpVerifyRequest()  {
		super(Message.MESSAGE_TYPE_FP_VERIFY_REQUEST);
	}
	
	/**
	 * Parse an FpVerifyRequest message from an InputStream. During the reading a lot of checks on the validity of the supplied data are performed. If one of them fails an exception is thrown.
	 * 
	 * @param in The InputStream to read the FpVerifyRequest from
	 * @param remoteAddr The IP address of the client that sent the FpVerifyRequest
	 * @param localAddr The IP of the local interface that received the FpVerifyRequest
	 * @return A FpVerifyRequest containing the information read from the InputStream (i.e. the FpVerifyRequest message) as well as the requesting and the receiving IP.
	 * @throws IOException
	 * @throws CertificateException
	 */
	public static FpVerifyRequest readFromStream(InputStream in, String remoteAddr, String localAddr) throws IOException  {

		// fpvr is the FpVerifyRequest that will be returned
		FpVerifyRequest fpvr = new FpVerifyRequest();

		// Add the IP that sent the request-message and the IP that received it
		fpvr.setLocalAddr(InetAddress.getByName(localAddr));
		fpvr.setRemoteAddr(InetAddress.getByName(remoteAddr));

		// Now Parse the InputStream
		BufferedInputStream bin = new BufferedInputStream(in);

		// First Verify the message is actually of type MESSAGE_TYPE_FP_VERIFY_REQUEST
		int messageType = bin.read();
		if (messageType != Message.MESSAGE_TYPE_FP_VERIFY_REQUEST) {
			throw new IllegalArgumentException("The provided messageType " + messageType + " was not expected");
		}

		// Then read the message length field
		byte[] messageLengthB = new byte[2];
		if (bin.read(messageLengthB) != messageLengthB.length) {
			throw new IOException("Reached unexpected end of stream while extracting message length.");
		}
		int messageLength = Message.byteArrayToInt(messageLengthB);
		
		// Verify that the message format version corresponds to MESSAGE_TYPE_FP_VERIFY_REQUEST_FORMAT_VERSION
		int messageFormatVersion = bin.read();
		if (messageFormatVersion != MESSAGE_TYPE_FP_VERIFY_REQUEST_FORMAT_VERSION) {
			throw new IllegalArgumentException("The provided messageFormatVersion " + messageFormatVersion + " was not expected");
		}
		
		// Read the queried host's IPv4 address
		byte[] ipAddress = new byte[4];
		if (bin.read(ipAddress) != ipAddress.length) {
			throw new IOException("Reached unexpected end of stream while extracting host IP address.");
		}
		fpvr.setHostIP(arrayToIpv4(ipAddress));
		
		// Read the queried host's port number
		byte[] portB = new byte[2];
		if (bin.read(portB) != portB.length) {
			throw new IOException("Reached unexpected end of stream while extracting host port number.");
		}
		byte[] portLeadingZeroB = { 0, portB[0], portB[1] };
		int port = new BigInteger(portLeadingZeroB).intValue();

		// ... and check if it is a valid 16 bit Integer > 0
		if (port <= 0 || port >= (1 << 16)) {
			throw new IllegalArgumentException("The provided port is outside the valid range: " + port);
		}
		fpvr.setHostPort(port);
		
		// Read fingerprint key type
		int keyTypeB = bin.read();
		KeyType keyType = KeyType.values()[keyTypeB];
		fpvr.setKeyType(keyType);
		
		// Read ECDSA fingerprint NID
		byte[] keyNidB = new byte[2];
		if (bin.read(keyNidB) != keyNidB.length) {
			throw new IOException("Reached unexpected end of stream while extracting ECDSA NID.");
		}
		int keyNid = new BigInteger(keyNidB).intValue();
		fpvr.setKeyNid(keyNid);
		
		// Read fingerprint
		byte[] fingerprintB = new byte[messageLength - (1 + 2 + 1 + 4 + 2 + 1 + 2)];
		if (bin.read(fingerprintB) != fingerprintB.length) {
			throw new IOException("Reached unexpected end of stream while extracting fingerprint.");
		}
		fpvr.setFingerprint(new String(fingerprintB, "UTF-8"));		

		return fpvr;
	}

	/**
	 * @return the keyNid
	 */
	public int getKeyNid() {
		return keyNid;
	}

	/**
	 * @param keyNid the keyNid to set
	 */
	public void setKeyNid(int keyNid) {
		this.keyNid = keyNid;
	}

	/**
	 * @return The IP of the Host from which the certificate has been received
	 */
	public InetAddress getHostIP() {
		return hostIP;
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
	 * @return The IP that sent the CertVerifyRequest-message
	 */
	public InetAddress getRemoteAddr() {
		return remoteAddr;
	}
	
	/**
	 * @return the keyType
	 */
	public KeyType getKeyType() {
		return keyType;
	}

	/**
	 * @return the fingerprint
	 */
	public String getFingerprint() {
		return fingerprint;
	}


	/**
	 * @param fingerprint the fingerprint to set
	 */
	public void setFingerprint(String fingerprint) {
		this.fingerprint = fingerprint;
	}


	/**
	 * @param keyType the keyType to set
	 */
	public void setKeyType(KeyType keyType) {
		this.keyType = keyType;
	}

	/**
	 * @param hostIP The IP of the Host from which the certificate has been received
	 */
	public void setHostIP(InetAddress hostIP) {
		this.hostIP = hostIP;
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
	 * @param remoteAddr The IP that sent the CertVerifyRequest-message
	 */
	public void setRemoteAddr(InetAddress remoteAddr) {
		this.remoteAddr = remoteAddr;
	}
	
	/**
	 * Converts a 4 byte array in network byte order into an IPv4 address.
	 * 
	 * @param bytes Byte array holding IP address
	 * @return InetAddress object holding the IPv4 address
	 */
	private static InetAddress arrayToIpv4(byte[] bytes) {
		if (bytes.length != 4) {
			throw new IllegalArgumentException("Number of bytes (" + bytes.length + ") was not expected");
		}
		
		// Check if all bytes are within the valid bounds
		if (bytes[0] == 0) {
			throw new IllegalArgumentException("Invalid leading zero byte");
		}
		
		try {
			return InetAddress.getByAddress(bytes);
		} catch (UnknownHostException e) {
			throw new IllegalArgumentException("Could not convert the byte array to an IP address");
		}
	}

	/* (non-Javadoc)
	 * @see crossbear.Message#writeContent(java.io.OutputStream)
	 */
	@Override
	protected void writeContent(OutputStream out) throws CertificateEncodingException, IOException {
		
		// Write message format version
		out.write(MESSAGE_TYPE_FP_VERIFY_REQUEST_FORMAT_VERSION);
		
		// Write IP address and port
		out.write(hostIP.getAddress());
		out.write((byte) (hostPort >> 8));
		out.write((byte) (hostPort & 255));
		
		// Write key type & NID
		out.write((byte) keyType.ordinal());
		out.write((byte) (keyNid >> 8));
		out.write((byte) (keyNid & 255));
		
		// Write fingerprint
		out.write(fingerprint.getBytes());
	}	
}
