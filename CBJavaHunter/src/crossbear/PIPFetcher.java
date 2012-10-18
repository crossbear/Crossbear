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

package crossbear;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import crossbear.messaging.Message;
import crossbear.messaging.PublicIPNotifRequest;
import crossbear.messaging.PublicIPNotification;

/**
 * This class provides the functionality to obtain a PublicIPNotification of a specific version from the Crossbear server.
 * 
 * @author Thomas Riedmaier
 *
 */
public class PIPFetcher {

	/**
	 * Adjust the size of a buffer so it can hold at least 1024 more bytes.
	 * 
	 * This function was created by the use of http://jajatips.blogspot.com/2008/11/reading-from-inputstream.html
	 * 
	 * @param in The buffer to adjust.
	 * @return A buffer with the same content as "in" that is able to hold at least 1024 more bytes
	 */
	private static ByteBuffer adjustBufferSize(ByteBuffer in) {
		
		// If "in" can hold at least 1024 more bytes then return "in"
		ByteBuffer result = in;
		if (in.remaining() < 1024) {
			
			// Else create a new buffer with double the capacity of "in" (which is assumed to have initial capacity of 1024)
			result = ByteBuffer.allocate(in.capacity() * 2);
			
			// Set the limit to the current position in buffer and set the position to zero
			in.flip();
			
			// Put the original buffer into the new buffer
			result.put(in);
		}

		return result;
	}

	/**
	 * Decrypt an array of bytes using the AES/CBC/PKCS7Padding encryption scheme.
	 * 
	 * Please Note: "AES/CBC/PKCS7Padding" requires the Bouncy-Castle Crypto-Provider to be installed!
	 * 
	 * @param AESKeyBytes The key to use
	 * @param cipherText The AES-encrypted data to decrypt
	 * @return The decrypted data
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 */
	private static byte[] AESDecrypt(byte[] AESKeyBytes, byte[] cipherText) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

		// CBC-mode requires an IV. It is assumed that the first 16 bytes of the cipherText constitute the IV.
		IvParameterSpec ivSpec = new IvParameterSpec(Arrays.copyOfRange(cipherText, 0, 16));

		// Specify an AES/CBC/PKCS7Padding cipher (requires BouncyCastle Crypto provider)
		SecretKeySpec skeySpec = new SecretKeySpec(AESKeyBytes, "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");

		// Initialize the cipher
		cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec);

		// Perform the decryption and return its result
		return cipher.doFinal(Arrays.copyOfRange(cipherText, 16, cipherText.length));

	}


	/**
	 * Generate a random AES-256 key
	 * 
	 * Please Note: This function requires the Bouncy-Castle Crypto-Provider to be installed!
	 * 
	 * @return A random AES-256 key
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 */
	private static SecretKey generateRandomAES256Key() throws NoSuchAlgorithmException, NoSuchProviderException {
		
		// Use Bouncy-Castle to generate a random AES-256 key ...
		KeyGenerator KeyGen = KeyGenerator.getInstance("AES", "BC");
		KeyGen.init(256);

		// ... and return it.
		return KeyGen.generateKey();
	}
	
	/**
	 * Read the remaining bytes from an InputStream and return them as a byte[]
	 * 
	 * This code was created by the use of http://jajatips.blogspot.com/2008/11/reading-from-inputstream.html
	 * 
	 * @param is The InputStream to read from
	 * @return The bytes that were read from the InputStream
	 * @throws IOException
	 */
	private static byte[] readStreamRemainder(InputStream is) throws IOException {
		
		// Create a channel for the InputStream
		ReadableByteChannel bc = Channels.newChannel(is);
		
		// Allocate a reading buffer
		ByteBuffer bb = ByteBuffer.allocate(1024);

		// Read bytes from the channel until no more bytes can be read and but them in the reading buffer
		while (bc.read(bb) != -1) {
			// To prevent the buffer from overflowing: resize it if it became too small
			bb = adjustBufferSize(bb);
		}
		
		// Create a byte[] and copy the buffer's content into that array
		byte[] result = new byte[bb.position()];
		bb.position(0);
		bb.get(result);

		// Return that byte[]
		return result;
	}
	
	/**
	 * Perform a RSA encryption in RSA/None/OAEPWithSHA1AndMGF1Padding-Mode
	 * 
	 * Please Note: "RSA/None/OAEPWithSHA1AndMGF1Padding" requires the Bouncy-Castle Crypto-Provider to be installed!
	 * 
	 * @param pkey The public key to use
	 * @param plainText The bytes to encrypt
	 * @return The RSA-encrypted version of "plainText"
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 */
	private static byte[] RSAEncrypt(PublicKey pkey, byte[] plainText) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
			NoSuchPaddingException {

		// Use RSA/None/OAEPWithSHA1AndMGF1Padding since RSA/NONE/NoPadding is not secure
		Cipher rsaOAEPCipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding", "BC");

		// Initialization of the cipher
		rsaOAEPCipher.init(Cipher.ENCRYPT_MODE, pkey);

		// Do the actual encryption and return the result
		return rsaOAEPCipher.doFinal(plainText);
	}

	// The certificate of the Crossbear-Server
	private X509Certificate cbServerCert;

	// The IPv6-address of the Crossbear-Server
	private Inet6Address sip6;

	// The IPv4-address of the Crossbear-Server
	private Inet4Address sip4;

	/**
	 * Create a new Public-IP-Fetcher.
	 * 
	 * @param cbServerHost The Hostname of the Crossbear server (e.g. crossbear.net.in.tum.de)
	 * @param cbServerCert The certificate of the Crossbear-Server
	 * @throws UnknownHostException
	 * @throws NamingException
	 */
	public PIPFetcher(String cbServerHost, X509Certificate cbServerCert) throws UnknownHostException, NamingException {

		this.cbServerCert = cbServerCert;
		
		// Obtain the IP-addresses of the Crossbear-Server
		getServerIPs(cbServerHost);
		
	}

	/**
	 * Contact the Crossbear server and get a fresh PublicIPNotification of a specific IP-version
	 * 
	 * @param ipVersion The IP-version of the PublicIPNotification that is to obtain from the Crossbear-Server (4 or 6)
	 * @return A fresh PublicIPNotification of a specific IP-version, or null if the server could not be contacted using that IP-version 
	 * @throws Exception
	 */
	public PublicIPNotification getFreshPublicIPNot(int ipVersion) throws Exception {
		
		// Generate a random AES-256 key
		SecretKey aesKey = generateRandomAES256Key();

		// Encrypt the key using the Crossbear-Server's public key
		byte[] rsaEncryptedKey = RSAEncrypt(cbServerCert.getPublicKey(), aesKey.getEncoded());

		// Put the RSA-encrypted AES-key in a PublicIPNotifRequest ...
		PublicIPNotifRequest pipReq = new PublicIPNotifRequest();
		pipReq.setRsaEncryptedKey(rsaEncryptedKey);

		// And send this request to the server
		byte[] serverReply = sendPubIPRequestToCBServer(ipVersion, pipReq);
		
		// In case the server could not be contacted using the specified IP-version: return null
		if (serverReply == null)
			return null;

		// Decrypt the server's reply ...
		byte[] decryptedServerReply = AESDecrypt(aesKey.getEncoded(), serverReply);

		// ... and validate it. The reply has the format PLAINTEXT|SUPPOSED_HASH(32bytes). First: Split the server's reply:
		byte[] supposedHash = Arrays.copyOfRange(decryptedServerReply, decryptedServerReply.length - 32, decryptedServerReply.length);
		byte[] plaintext = Arrays.copyOfRange(decryptedServerReply, 0, decryptedServerReply.length - 32);
		
		// Calculate the plaintext's REAL hash
		byte[] actualHash = CertificateManager.SHA256(plaintext);

		// Compare the actual hash with the supposed hash. If they don't match then somebody tampered with the data
		if (!Arrays.equals(supposedHash, actualHash)) {
			throw new Exception("Decoding a PublicIPNotification failed because of an invalid Checksum!");
		}
		
		// Assert that the decrypted plaintext is a MESSAGE_TYPE_PUBLIC_IP_NOTIFX-message
		if (plaintext[0] != Message.MESSAGE_TYPE_PUBLIC_IP_NOTIF4 && plaintext[0] != Message.MESSAGE_TYPE_PUBLIC_IP_NOTIF6) {
			throw new Exception("Decoding a PublicIPNotification failed because of an unexpected message Type!");
		}

		// Convert the plaintext into a PublicIPNotification-object and return it
		return new PublicIPNotification(Arrays.copyOfRange(plaintext, 3, plaintext.length), ipVersion);

	}

	/**
	 * Perform a DNS-request on a server's Hostname. If a IPv4-address is found for that server, it is stored in "sip4"; if a IPv6-address is found, it is stored in "sip6".
	 * 
	 * @param serverHostname The Hostname to lookup (e.g. www.somedomain.org)
	 * @throws UnknownHostException
	 * @throws NamingException
	 */
	private void getServerIPs(String serverHostname) throws UnknownHostException, NamingException {
		
		// Reset the server's IPs
		sip4 = null;
		sip6 = null;
		
		// Perform the actual DNS-request using the javax.naming.directory-API
		DirContext ictx = new InitialDirContext();
		Attributes a = ictx.getAttributes("dns:/" + serverHostname, new String[] { "A", "AAAA" });

		// Parse the result of the DNS-request:
		NamingEnumeration<? extends Attribute> all = a.getAll();
		while (all.hasMore()) {
			Attribute attr = (Attribute) all.next();

			// If a IPv4-address was found for the server: Store it in "sip4"
			if (attr.getID().equals("A")) {
				sip4 = (Inet4Address) InetAddress.getByName(attr.get(0).toString());
			
			// If a IPv6-address was found for the server: Store it in "sip6"
			} else if (attr.getID().equals("AAAA")) {
				sip6 = (Inet6Address) InetAddress.getByName(attr.get(0).toString());
			}
		}

	}

	/**
	 * Try to send a PublicIPNotifRequest to the Crossbear-Server using a specific IP-version and return the server's reply.
	 * 
	 * @param ipVersion The IP-version to use (4 or 6)
	 * @param pipReq The PublicIPNotifRequest to send
	 * @return The server's reply if it was possible to contact it, else null.
	 * @throws NoSuchAlgorithmException
	 * @throws KeyManagementException
	 * @throws InvalidKeyException
	 * @throws CertificateEncodingException
	 * @throws NoSuchProviderException
	 * @throws SQLException
	 */
	private byte[] sendPubIPRequestToCBServer(int ipVersion, PublicIPNotifRequest pipReq) throws NoSuchAlgorithmException, KeyManagementException, InvalidKeyException, CertificateEncodingException,
			NoSuchProviderException, SQLException {

		try {
			
			// Get the IP-address of the Crossbear-Server to connect to (depending on the IP-version to use)
			String cbIP;
			if (ipVersion == 4) {
				if (sip4 == null)
					throw new IOException();
				cbIP = sip4.getHostAddress();
			} else {
				if (sip6 == null)
					throw new IOException();
				cbIP = "[" + sip6.getHostAddress() + "]";
			}

			// Use that IP-address to build a URL pointing to the Crossbear-Server's getPublicIP-page
			URL url = new URL("http://" + cbIP + ":80/getPublicIP.jsp");

			// Open a HttpURLConnection for that URL
			HttpURLConnection conn = (HttpURLConnection) url.openConnection();

			// Send the PublicIPNotifRequest to the server
			conn.setDoOutput(true);
			OutputStream out = conn.getOutputStream();
			out.write(pipReq.getBytes());
			out.flush();

			// Read the server's response
			InputStream is = conn.getInputStream();
			byte[] response = readStreamRemainder(is);
			
			// Close all opened Streams
			is.close();
			out.close();

			// Finally: Return the server's response
			return response;

		} catch (IOException e) {
			// If it was not possible to connect to the Crossbear-Server using "ipVersion" return null
			System.err.println("Could not connect to the crossbear server using IPv" + ipVersion);
			return null;
		}

	}
}
