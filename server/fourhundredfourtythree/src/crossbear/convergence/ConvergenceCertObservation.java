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
