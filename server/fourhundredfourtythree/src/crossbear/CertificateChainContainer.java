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

import java.net.InetAddress;
import java.security.cert.X509Certificate;

/**
 * Container class to return both, a server's certificate chain and its IP-address from a function at the same time
 * 
 * @author Thomas Riedmaier
 *
 */
public class CertificateChainContainer {

	// The server's certificate chain
	private X509Certificate[] chain;
	
	// The IP-address from which the certificate chain was obtained
	private InetAddress serverAddress;

	/**
	 * Create a new CertificateChain-object as a container for a X509Certificate[] and an InetAddress
	 * @param chain The certificate chain to store in this object
	 * @param serverAddress The InetAddress to store in this object
	 */
	public CertificateChainContainer(X509Certificate[] chain, InetAddress serverAddress) {
		this.chain = chain;
		this.serverAddress = serverAddress;
	}

	/**
	 * @return the server's certificate chain
	 */
	public X509Certificate[] getChain() {
		return chain;
	}

	/**
	 * @return the IP-address from which the certificate chain was obtained
	 */
	public InetAddress getServerAddress() {
		return serverAddress;
	}

}
