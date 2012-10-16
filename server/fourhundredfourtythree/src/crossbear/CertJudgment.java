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

/**
 * Crossbear doesn't judge certificates as good or bad. Instead it considers various facets of the certificate, judges them, rates them and then combines them into a final report. Each Judgment is
 * hereby stored as a CertJudgment-object.
 * 
 * A CertJudgment could e.g. be 
 * - "VALIDITY: NOT NOW", -20 
 * - "CERTCOMPARE: same", 80 
 * - ...
 * 
 * @author Thomas Riedmaier
 * 
 */
public class CertJudgment {

	private final String what;
	private final int rating;

	/**
	 * Creates a new CertJudgment-object meant to store a Judgment about a certificate
	 * 
	 * @param what The textual representation of the Judgment
	 * @param rating The rating of the Judgment
	 */
	public CertJudgment(String what, int rating) {
		this.what = what;
		this.rating = rating;
	}

	/**
	 * @return The rating of the Judgment
	 */
	public int getRating() {
		return rating;
	}

	/**
	 * @return The textual representation of the Judgment
	 */
	public String getText() {
		return what;
	}
}
