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
