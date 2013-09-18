
package crossbear;

import java.util.LinkedList;
import java.util.Arrays;
import java.util.Iterator;

import java.io.UnsupportedEncodingException;
import java.io.IOException;

import java.net.InetSocketAddress;
import java.net.InetAddress;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.cert.Certificate;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.MessageDigest;
import java.security.KeyManagementException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;

import org.bouncycastle.util.encoders.Base64;


class ChainHashCalculator {
    public static String getCertChainMD5(LinkedList<X509Certificate> certList) throws CertificateEncodingException, NoSuchAlgorithmException, UnsupportedEncodingException {
	StringBuilder re = new StringBuilder();

	// Go through all Elements of the chain
	Iterator<X509Certificate> iter = certList.iterator();
	while (iter.hasNext()) {
	    // Get the PEM-encoding for each certificate,
	    // calculate its MD5-hash and append its
	    // HEX-String representation to the output
	    String hulla = getPemEncoding(iter.next());
	    //System.out.println("PEM encoding: " + hulla);
	    String m = byteArrayToHexString(MD5(hulla.getBytes("UTF-8")));
	    //System.out.println("My hash is: " + m);
	    re.append(m);
	}

	return re.toString();
    }

    public static String byteArrayToHexString(byte[] b) {
	String result = "";
	for (int i = 0; i < b.length; i++) {
	    result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
	}
	return result;
    }


    public static byte[] hexStringToByteArray(String s) {
	// Pad the string to an even number of characters
	if(s.length() %2 != 0){
	    s = "0"+s;
	}
		
	int len = s.length();
	byte[] data = new byte[len / 2];
	for (int i = 0; i < len; i += 2) {
	    data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
	}
	return data;
    }

    public static byte[] SHA256(byte[] data) throws NoSuchAlgorithmException {
	MessageDigest md = MessageDigest.getInstance("SHA-256");
	return md.digest(data);
    }

    public static byte[] SHA1(byte[] data) throws NoSuchAlgorithmException {
	MessageDigest md = MessageDigest.getInstance("SHA-1");
	return md.digest(data);
    }

    private static String getPemEncoding(X509Certificate cert) throws CertificateEncodingException {

	// Get the bytes of the certificate(DER) and encode them in base64
	String base64EncodedCert = new String(Base64.encode(cert.getEncoded()));

	// Write the PEM header
	String re = "-----BEGIN CERTIFICATE-----\n";

	// Write the certificate data in lines of 64 chars
	int len = base64EncodedCert.length();
	for (int i = 0; i < len; i += 64) {
	    re += base64EncodedCert.substring(i, Math.min(len, i + 64)) + "\n";
	}

	// Write the PEM trailer
	re += "-----END CERTIFICATE-----";

	// Return the PEM-representation of the certificate
	return re;
    }

    public static byte[] MD5(byte[] data) throws NoSuchAlgorithmException {
	MessageDigest md = MessageDigest.getInstance("MD5");
	return md.digest(data);
    }


    public static CertificateChainContainer getCertChainFromServer(String host, int port) throws KeyManagementException, IOException, NoSuchAlgorithmException {

	IOException lastCaughtException = null;

	// Attempt twice: Once with TLS/SNI (required for SNI systems and preferred mode for flexible systems)
	// and once with SSL3 using SSLv2Handshake (required for some older systems)
	for (int numberOfTries = 0; numberOfTries < 2; numberOfTries++) {
	    try {

		// Force the connection even if the server uses deprecated algorithms
		// since Security.setProperty("jdk.certpath.disabledAlgorithms", "BLABLABLA");
		// is not working when called from jsp it has to be set in the java.security
		// file of the current jvm

		// Force the connection even if the certificate is untrusted
		SSLContext sc = SSLContext.getInstance("SSL");
		TrustManager[] trustAllCerts = new TrustManager[] { new TrustAllCertificatesTM()};
		sc.init(null, trustAllCerts, new java.security.SecureRandom());
				
		// Create and open a Socket for the connection
		SSLSocket sock;
		if (numberOfTries == 0) {
					
		    // Opening the connection has to be done in the createSocket-method or else SNI will not work
		    sock = (SSLSocket) sc.getSocketFactory().createSocket(host, port);
		} else {
					
		    // In case the the server doesn't support TLS/SSL3 try to use SSLv2Handshake mode
		    sock = (SSLSocket) new SSLv2EnabledSocketFactory(sc).createSocket();
					
		    // Opening the connection in an extra call allows to specify the timeout value
		    sock.connect(new InetSocketAddress(host, port), 3000);
		}				

		// Get the server's IP-Address
		InetAddress serverAddress = ((InetSocketAddress)sock.getRemoteSocketAddress()).getAddress();
				
		// Make sure the handshaking attempt does not take forever
		sock.setSoTimeout(3000);
				
		// Get the certificate chain provided by the server
		Certificate certs[] = sock.getSession().getPeerCertificates();
				
		return new CertificateChainContainer((certs instanceof X509Certificate[]) ? (X509Certificate[]) certs : null, serverAddress);

	    } catch (IOException e) {
		lastCaughtException = e;
	    }
	}
	// TODO uh, wait a second -- this looks a lot as if we throw an IOException if we cannot connect at all
	// - and that IOException would wander up the whole stack and crash the main
	throw lastCaughtException;

    }



    public static void main(String[] args) throws Exception {
	LinkedList<X509Certificate> certchain = new LinkedList<X509Certificate>(Arrays.asList(getCertChainFromServer("saanet.sg", 443).getChain()));
	X509Certificate servercert = certchain.pop();
	String certSHA256 = byteArrayToHexString(SHA256(servercert.getEncoded()));
	String certChainMd5 = getCertChainMD5(certchain);
	String certChainSHA256 = byteArrayToHexString(SHA256(hexStringToByteArray(certSHA256+certChainMd5)));
	System.out.println(certChainSHA256);
    }
}
