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
