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

package crossbear;

import java.io.FileInputStream;
import java.io.IOException;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.sql.SQLException;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import crossbear.messaging.PublicIPNotifRequest;
import crossbear.messaging.PublicIPNotification;

/**
 * PublicIPNotifProcessor is the class used by getPublicIP.jsp to generate a encrypted and integrity protected PublicIPNotification out of a PublicIPNotifRequest
 * 
 * To guarantee the confidentiality and integrity of the PublicIPNotification on it's way to the client the PublicIPNotification-Message is first hashed and concatenated with it's hash. The result will then be AES
 * encrypted and sent to the client. This procedure is necessary since getPublicIP.jsp is accessed over plain http and thus there is no ssl protection of the messages. 
 * 
 * The AES key that is required for the transmission is provided by the client in RSA-encrypted version.
 * 
 * @author Thomas Riedmaier
 * 
 */
public class PublicIPNotifProcessor {

	/**
	 * Encrypt an array of bytes with the AES/CBC/PKCS7Padding encryption scheme
	 * 
	 * Please Note: "AES/CBC/PKCS7Padding" requires the Bouncy-Castle Crypto-Provider to be installed!
	 * 
	 * @param AESKeyBytes The key to use
	 * @param cleartext The data to encrypt
	 * @return The AES-encrypted cleartext
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 */
	private static byte[] AESEncrypt(byte[] AESKeyBytes, byte[] cleartext) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException,
			NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {

		// CBC-mode requires an IV
		IvParameterSpec iv = generateRandomIV(16);

		// specify an AES/CBC/PKCS7Padding cipher (requires BouncyCastle Crypto provider)
		SecretKeySpec skeySpec = new SecretKeySpec(AESKeyBytes, "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");

		// init the cipher
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

		// perform the encryption
		return concatByteArrays(iv.getIV(), cipher.doFinal(cleartext));

	}

	/**
	 * Concatenate two byte arrays: Create a byte array that is large enough to contain both arrays and then copy b1
	 * to the beginning of the new array and b2 to the end of the larger array.
	 * 
	 * e.g. b1 = {1,2,3}; b2 = {4,5}; return will be {1,2,3,4,5}
	 * 
	 * @param b1 first byte array to concatenate
	 * @param b2 second byte array to concatenate
	 * @return concatenation of b1 and b2
	 */
	private static byte[] concatByteArrays(byte[] b1, byte[] b2) {
		int totalLength = b1.length + b2.length;
		byte[] re = new byte[totalLength];

		System.arraycopy(b1, 0, re, 0, b1.length);
		System.arraycopy(b2, 0, re, b1.length, b2.length);

		return re;
	}

	/**
	 * AES in CBC requires a random Initialization Vector. This vector is generated here
	 * 
	 * @param length of the desired IV
	 * @return an IV initialized with a byte[] of length "length"
	 */
	private static IvParameterSpec generateRandomIV(int length) {
		// create buffer for iv creation
		byte[] iv = new byte[length];

		// fill buffer with random data
		(new Random()).nextBytes(iv);

		// use buffer to create a random initialization vector (iv)
		IvParameterSpec ips = new IvParameterSpec(iv);

		return ips;
	}

	/**
	 * Extract a keypair from a keystore and return it as a KeyPair. 
	 * 
	 * The code was created by the use of http://www.exampledepot.com/egs/java.security/GetKeyFromKs.html
	 * 
	 * @param keystore The keystore that contains the keypair
	 * @param keyAlias The name of the key
	 * @param keyPassword The password to extract the key
	 * @return The public and private key of the key with alias keyAlias as a KeyPair
	 * @throws KeyStoreException
	 * @throws UnrecoverableKeyException
	 * @throws NoSuchAlgorithmException
	 */
	private static KeyPair getKeyPairFromKeystore(KeyStore keystore, String keyAlias, char[] keyPassword) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {

		// Get private key
		Key key = keystore.getKey(keyAlias, keyPassword);
		if (!(key instanceof PrivateKey))
			throw new UnrecoverableKeyException("keypair "+keyAlias+" could not be extracted from keystore "+keystore.toString()+" using password "+new String(keyPassword));

		// Get certificate of public key
		Certificate cert = keystore.getCertificate(keyAlias);

		// Get public key
		PublicKey publicKey = cert.getPublicKey();

		// Return it as a key pair
		return new KeyPair(publicKey, (PrivateKey) key);

	}

	/**
	 * Extract a keypair from a keystore-file and return it as a KeyPair. 
	 * 
	 * @param keystoreFilePath The path of the keystore that contains the keypair
	 * @param keyStorePassword The password to access the keystore
	 * @param keyAlias The name of the key
	 * @param keyPassword The password to extract the key
	 * @return The public and private key of the key with alias keyAlias as a KeyPair
	 * @throws IOException
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws UnrecoverableKeyException
	 */
	private static KeyPair getKeyPairFromKeystoreFile(String keystoreFilePath, String keyStorePassword, String keyAlias, String keyPassword) throws IOException, KeyStoreException, NoSuchAlgorithmException,
			CertificateException, UnrecoverableKeyException {

		// Create a keyStore Object
		KeyStore keyStore = KeyStore.getInstance("jks");

		// Link it to an existing key store on disk
		FileInputStream keyStoreInputStream = new FileInputStream(keystoreFilePath);

		// Load it's data
		keyStore.load(keyStoreInputStream, keyStorePassword.toCharArray());

		// Close the filestream
		keyStoreInputStream.close();

		// Extract the keyPair and return it
		return getKeyPairFromKeystore(keyStore, keyAlias, keyPassword.toCharArray());

	}

	/**
	 * Check if a byte[] implements a valid AES256 key.
	 * 
	 * Currently the only check implemented is if the length of the byte[] is 256 / 8
	 * 
	 * @param toCheck The byte[] to check
	 * @return True if it is a valid AES256Key and false otherwise
	 */
	private static boolean isValidAESKey(byte[] toCheck) {

		return toCheck.length == 256 / 8;
	}

	/**
	 * Perform a RSA decryption in RSA/None/OAEPWithSHA1AndMGF1Padding-Mode
	 * 
	 * Please Note: "RSA/None/OAEPWithSHA1AndMGF1Padding" requires the Bouncy-Castle Crypto-Provider to be installed!
	 * 
	 * @param pkey The private key to use
	 * @param cryptText The crypto text to decrypt
	 * @return The cleartext of the crypto text
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 */
	private static byte[] RSADecrypt(PrivateKey pkey, byte[] cryptText) throws IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchProviderException,
			NoSuchPaddingException, InvalidKeyException {

		// Use RSA/None/OAEPWithSHA1AndMGF1Padding since RSA/NONE/NoPadding is not secure
		Cipher rsaOAEPCipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding", "BC");

		// Initialization of the cipher
		rsaOAEPCipher.init(Cipher.DECRYPT_MODE, pkey);

		// Do the actual decryption and return the result (quite slow: it takes about 30 ms!)
		return rsaOAEPCipher.doFinal(cryptText);
	}

	/**
	 * Calculate a SHA256 hash over a byte[]
	 * 
	 * @param data The array to calculate the hash of
	 * @return a byte[] of 32 bytes length containing the SHA256 hash of "data"
	 * @throws NoSuchAlgorithmException
	 */
	private static byte[] SHA256(byte[] data) throws NoSuchAlgorithmException {

		MessageDigest md = MessageDigest.getInstance("SHA-256");
		return md.digest(data);

	}

	//The RSA keypair used by the Crossbear server
	private final KeyPair crossbearRSAKeyPair;

	/**
	 * Creating a new PublicIPNotifProcessor. During the creation the RSA keypair of the server is loaded from disc since it is required to perform the generateEncryptedPublicIPNotif function. Putting
	 * this functionality in the constructor speeds up per-page-processing a lot.
	 * 
	 * @param keystoreFilePath The path of the keystore that contains the keypair
	 * @param keyStorePassword The password to access the keystore
	 * @param keyAlias The name of the key
	 * @param keyPassword The password to extract the key
	 * @throws UnrecoverableKeyException
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 */
	public PublicIPNotifProcessor(String keystoreFilePath, String keyStorePassword, String keyAlias, String keyPassword) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {

		// Load the server's RSA keypair from disc
		crossbearRSAKeyPair = PublicIPNotifProcessor.getKeyPairFromKeystoreFile(keystoreFilePath, keyStorePassword, keyAlias, keyPassword);
	}

	/**
	 * Take a PublicIPNotifRequest and decrypt the contained AES-key. Then take the client's public IP and generate a PublicIPNotification-message. Hash the message and encrypt both with the client's
	 * AES-key. Then return the result.
	 * 
	 * @param pipnr The PublicIPNotifRequest issued by the client
	 * @param db The database connection to use (required to add a HMAC to the PublicIPNotification-message)
	 * @return The AES encrypted concatenation of the PublicIPNotification-message and its hash
	 * @throws InvalidKeyException
	 * @throws CertificateEncodingException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws IOException
	 * @throws SQLException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 */
	public byte[] generateEncryptedPublicIPNotif(PublicIPNotifRequest pipnr, Database db) throws InvalidKeyException, CertificateEncodingException, NoSuchAlgorithmException, NoSuchProviderException,
			IOException, SQLException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException {

		// Decrypt the AES-key
		byte[] decryptedRSAKey = RSADecrypt(crossbearRSAKeyPair.getPrivate(), pipnr.getRsaEncryptedKey());

		// Make sure it is valid
		if (!isValidAESKey(decryptedRSAKey)) {
			throw new IllegalArgumentException("Decrypting the content of the PublicIPNotifRequest did not result in a valid AES key (length was: "+decryptedRSAKey.length+").");
		}

		// Generate the PublicIPNotification containing the public IP of the client
		byte[] messageBytes = new PublicIPNotification(pipnr.getRemoteAddr(), db).getBytes();

		// Concatenate it with its hash
		byte[] replyPayload = concatByteArrays(messageBytes, SHA256(messageBytes));

		// Encrypt the concatenation using the AES-key supplied by the client
		byte[] encryptedReply = AESEncrypt(decryptedRSAKey, replyPayload);
		
		// Return the result
		return encryptedReply;

	}
}
