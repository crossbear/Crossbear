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
