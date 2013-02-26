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
import java.security.spec.InvalidKeySpecException;
import java.security.interfaces.RSAPrivateKey;
import java.security.SignatureException;
import java.security.InvalidKeyException;

import crossbear.CertificateManager;


public class SignatureMessage extends Message {

	private byte[] signatureBytes;
	
	public SignatureMessage(byte[] data) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException {
		super(Message.MESSAGE_TYPE_SIGNATURE);
		// Also needs the server certificate to calculate the correct signature
		// Calculate the signature for the message here.
		// Key ist im fourfourthree-ordner
		File keyfile = new File("/path/to/key");
		BufferedInputStream bis = new BufferedInputStream(new FileInputStream(keyfile));
		// XXX Possible bug with large key files
		byte[] keybytes = new byte[(int)keyfile.length()];
		bis.read(keybytes);
		bis.close();
		KeyFactory kf = KeyFactory.getInstance("RSA");
		// Do this from a PEM encoded file.
		KeySpec ks = new PKCS8EncodedKeySpec(keybytes);
		RSAPrivateKey privKey = ((RSAPrivateKey)kf.generatePrivate(ks));
		// XXX is this an acceptable algorithm?
		Signature sig = Signature.getInstance("SHA256withRSA");
		sig.initSign(privKey);
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
