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
