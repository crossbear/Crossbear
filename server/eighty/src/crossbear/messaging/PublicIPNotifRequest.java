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
