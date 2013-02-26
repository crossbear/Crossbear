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


public class SignatureMessage extends Message {
    
	public SignatureMessage(byte[] bytes) {
		// Calculate the signature for the message here.
		super(Message.MESSAGE_TYPE_SIGNATURE);
	}

	protected void writeContent(OutputStream out) throws MessageSerializationException {
		// Placeholder
		return;
	}

}
