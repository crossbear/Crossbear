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

import java.sql.Timestamp;


/**
 * When queried for a host a Notary will respond with a list of ConvergenceCertObservations of the form
 * {"timestamp":{"finish":"1318361407","start":"1317392198"},"fingerprint":"56:F6:A9:A9:D2:ED:FD:1A:B2:F9:63:7E:D3:51:AC:56:B3:59:A9:8D"}
 * 
 * Crossbear will convert this String-representation into a ConvergenceCertObservation-Object with the same content. This Object is defined by this class.
 * 
 * @author Thomas Riedmaier
 *
 */
public class ConvergenceCertObservation {

	// The Hostname of the server on which the ConvergenceCertObservation was made
	private final String hostPort;
	
	// The SHA-1 Hash of the certificate of the ConvergenceCertObservation in HexString-representation (i.e. the "fingerprint"-field)
	private final String certHash;
	
	// The "start"-Timestamp of the ConvergenceCertObservation which is assumed to be the first time that Convergence observed the ConvergenceCertObservation's certificate
	private final Timestamp firstObservation;
	
	// The "finish"-Timestamp of the ConvergenceCertObservation which is assumed to be the last time that Convergence observed the ConvergenceCertObservation's certificate
	private final Timestamp lastObservation;
	
	// The Timestamp of the last time that Crossbear received the ConvergenceCertObservation from a Convergence Notary
	private final Timestamp lastUpdate;

	/**
	 * Create a new ConvergenceCertObservation-object.
	 * 
	 * @param hostPort The Hostname and port of the server on which the ConvergenceCertObservation was made e.g. encrypted.google.com:443
	 * @param certHash The SHA-1 Hash of the certificate of the ConvergenceCertObservation in HexString-representation
	 * @param firstObservation The Timestamp of the first time that Convergence observed the ConvergenceCertObservation's certificate
	 * @param lastObservation The Timestamp of the last time that Convergence observed the ConvergenceCertObservation's certificate
	 * @param lastUpdate The Timestamp of the last time that Crossbear received the ConvergenceCertObservation from a Convergence Notary
	 */
	public ConvergenceCertObservation(String hostPort, String certHash, Timestamp firstObservation, Timestamp lastObservation, Timestamp lastUpdate){
		this.hostPort = hostPort;
		this.certHash = certHash;
		this.firstObservation = firstObservation;
		this.lastObservation = lastObservation;
		this.lastUpdate = lastUpdate;
	}

	/**
	 * @return The SHA-1 Hash of the certificate of the ConvergenceCertObservation in HexString-representation
	 */
	public String getCertHash() {
		return certHash;
	}

	/**
	 * @return The Timestamp of the first time that Convergence observed the ConvergenceCertObservation's certificate
	 */
	public Timestamp getFirstObservation() {
		return firstObservation;
	}

	/**
	 * @return The Hostname of the server on which the ConvergenceCertObservation was made
	 */
	public String getHostPort() {
		return hostPort;
	}

	/**
	 * @return The Timestamp of the last time that Convergence observed the ConvergenceCertObservation's certificate
	 */
	public Timestamp getLastObservation() {
		return lastObservation;
	}

	/**
	 * @return The Timestamp of the last time that Crossbear received the ConvergenceCertObservation from a Convergence Notary
	 */
	public Timestamp getLastUpdate() {
		return lastUpdate;
	}
	
}
