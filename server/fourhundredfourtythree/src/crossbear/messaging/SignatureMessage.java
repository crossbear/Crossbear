package crossbear.messaging;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileInputStream;
import java.io.File;
import java.net.InetAddress;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.KeySpec;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.SignatureException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.UnrecoverableEntryException;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;


import org.bouncycastle.openssl.PEMReader;

import crossbear.CertificateManager;


public class SignatureMessage extends Message {

	private byte[] signatureBytes;
	
	
	public SignatureMessage(byte[] data, String keystoreFile, String keystorePass, String pkeyAlias, String pkeyPassword) throws IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, KeyStoreException, CertificateException, UnrecoverableEntryException {
		super(Message.MESSAGE_TYPE_SIGNATURE);
		// Also needs the server certificate to calculate the correct signature
		// Calculate the signature for the message here.
		// Key ist im fourfourthree-ordner
		KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(pkeyPassword.toCharArray());
		FileInputStream fis = new FileInputStream(keystoreFile);
		KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		keystore.load(fis, keystorePass.toCharArray());
		
		PrivateKey pk = ((KeyStore.PrivateKeyEntry)keystore.getEntry(pkeyAlias, protParam)).getPrivateKey();
		Signature sig = Signature.getInstance("SHA256withRSA");

		sig.initSign(pk);
		sig.update(data);
		signatureBytes = sig.sign();
	}

	protected void writeContent(OutputStream out) throws MessageSerializationException {
		try {
			out.write(signatureBytes);
		} catch (IOException e) {
			throw new MessageSerializationException("Failed to write to Output stream", e);
		}
		return;
	}

}
