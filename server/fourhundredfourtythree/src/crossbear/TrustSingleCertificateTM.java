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
*/

package crossbear;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.net.ssl.X509TrustManager;

import crossbear.messaging.Message;

/**
 * A TrustSingleCertificateTM is a X509TrustManager that is used for SSL-connections that should trust a single certificate only. If a contacted server sends any certificate but the trusted one an
 * exception will be thrown.
 * 
 * @author Thomas Riedmaier
 * 
 */
public class TrustSingleCertificateTM implements X509TrustManager {

	// The SHA256Hash of the only certificate that will be trusted 
	private final byte[] TrustedCertSHA256Hash;

	/**
	 * Create a X509TrustManager that will trust a single certificate only
	 * 
	 * @param TrustedCertSHA256Hash The SHA256Hash of the only certificate that will be trusted 
	 */
	public TrustSingleCertificateTM(byte[] TrustedCertSHA256Hash) {
		this.TrustedCertSHA256Hash = TrustedCertSHA256Hash;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see javax.net.ssl.X509TrustManager#checkClientTrusted(java.security.cert.X509Certificate[], java.lang.String)
	 */
	@Override
	public void checkClientTrusted(X509Certificate[] certs, String authType) throws CertificateException {
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see javax.net.ssl.X509TrustManager#checkServerTrusted(java.security.cert.X509Certificate[], java.lang.String)
	 */
	@Override
	public void checkServerTrusted(X509Certificate[] certs, String authType) throws CertificateException {

		try {
			// Check if the server's certificate's SHA256Hash matches the hash passed in the constructor
			if (!Arrays.equals(TrustedCertSHA256Hash, CertificateManager.SHA256(certs[0].getEncoded()))) {

				// If not throw an exception
				throw new CertificateException("An untrusted certificate was sent by the server: " + Message.byteArrayToHexString(CertificateManager.SHA256(certs[0].getEncoded())));
			}

		} catch (NoSuchAlgorithmException e) {
			throw new CertificateException("A NoSuchAlgorithmException was caught: " + e.getLocalizedMessage());
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see javax.net.ssl.X509TrustManager#getAcceptedIssuers()
	 */
	@Override
	public X509Certificate[] getAcceptedIssuers() {
		return null;
	}

}
