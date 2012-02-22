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
import java.net.InetAddress;


/**
 * A PublicIPNotifRequest is a message that is meant to be sent to the getPublicIP.jsp. It contains a AES256 key encrypted with the server's public RSA key. The AES- key is required to safely send the
 * PublicIPNotification-message to the client over a non-ssl connection.
 * 
 * @author Thomas Riedmaier
 * 
 */
public class PublicIPNotifRequest extends Message{
	
	/**
	 * Read a PublicIPNotifRequest from a input stream.
	 * 
	 * @param in InputStream to parse. This could e.g. be obtained by calling "request.getInputStream()" in a jsp
	 * @param remoteAddr The IP-Address that should be remembered as the IP that sent this request
	 * @return a new PublicIPNotifRequest containing the information read from the stream and the supplied remoteAddr
	 * @throws IOException
	 */
	public static PublicIPNotifRequest readFromStream(InputStream in, String remoteAddr) throws IOException {

		PublicIPNotifRequest pipnr = new PublicIPNotifRequest();

		pipnr.setRemoteAddr(InetAddress.getByName(remoteAddr));

		BufferedInputStream bin = new BufferedInputStream(in);

		// Assert message type is MESSAGE_TYPE_PUBLIC_IP_NOTIFICATION_REQUEST
		int messageType = bin.read();
		if (messageType != Message.MESSAGE_TYPE_PUBLIC_IP_NOTIFICATION_REQUEST) {
			throw new IllegalArgumentException("The provided messageType " + messageType + " was not expected");
		}

		// Read the message length field
		byte[] messageLengthB = new byte[2];
		if(bin.read(messageLengthB, 0, 2) != 2){
			throw new IOException("Reached unexpected end of stream while extracting message length.");
		}
		int messageLength = Message.byteArrayToInt(messageLengthB);
		
		// Assert the message length to be the length of a AES256 key + 3 byte header
		if(messageLength -3 != 2048 / 8){
			throw new IllegalArgumentException("Read message length \""+messageLength+"\" but expected was \""+ 2048 / 8+3+"\"");
		}
			
		// Extract and store the RsaEncryptedKey from the stream
		pipnr.setRsaEncryptedKey(readNBytesFromStream(bin, 2048 / 8));
		
		return pipnr;
	}

	// The IP from which this request was received
	private InetAddress remoteAddr;
	
	// The rsaEncryptedKey conatined within the message
	private byte[] rsaEncryptedKey;
	
	/**
	 * Create a new PublicIPNotifRequest-message without any content
	 */
	public PublicIPNotifRequest()  {
		super(Message.MESSAGE_TYPE_PUBLIC_IP_NOTIFICATION_REQUEST);
	}

	/**
	 * @return remoteAddr
	 */
	public InetAddress getRemoteAddr() {
		return remoteAddr;
	}

	/**
	 * @return rsaEncryptedKey
	 */
	public byte[] getRsaEncryptedKey() {
		return rsaEncryptedKey;
	}
	
	/**
	 * Set remoteAddr
	 * @param remoteAddr
	 */
	public void setRemoteAddr(InetAddress remoteAddr) {
		this.remoteAddr = remoteAddr;
	}

	/**
	 * Set rsaEncryptedKey
	 * @param rsaEncryptedKey
	 */
	public void setRsaEncryptedKey(byte[] rsaEncryptedKey) {
		this.rsaEncryptedKey = rsaEncryptedKey;
	}

	
	/* (non-Javadoc)
	 * @see crossbear.Message#writeContent(java.io.OutputStream)
	 */
	@Override
	protected void writeContent(OutputStream out) throws IOException {

		out.write(rsaEncryptedKey);
	}
}
