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

package crossbear.convergence;

/**
 * The Convergence-Servers that can be queried for a list of certificate observations are called "Notaries". Each Notary has a hostname by which it can be addressed and a certificate that it uses.
 * This class is the Object-representation of such a Notary.
 * 
 * @author Thomas Riedmaier
 * 
 */
public class ConvergenceNotary {

	// The Notary's Hostname
	private final String hostPort;
	
	// The SHA256-Hash of the certificate that the Notary uses
	private final String certSHA256Hash;

	/**
	 * Create a new Notary-Object
	 * 
	 * @param hostPort The Hostname and port of the notary e.g. notary.thoughtcrime.org:443
	 * @param certSHA256Hash The SHA256-hash of the Notary's certificate as a Hex-String
	 */
	public ConvergenceNotary(String hostPort, String certSHA256Hash) {
		this.hostPort = hostPort;
		this.certSHA256Hash = certSHA256Hash;
	}

	/**
	 * @return The SHA256-Hash of the certificate that the Notary uses
	 */
	public String getCertSHA256Hash() {
		return certSHA256Hash;
	}

	/**
	 * @return the Notary's Hostname
	 */
	public String getHostPort() {
		return hostPort;
	}

}
