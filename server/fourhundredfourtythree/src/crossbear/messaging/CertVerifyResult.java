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

    Original authors: Thomas Riedmaier, Ralph Holz (TU Muenchen, Germany)
*/

package crossbear.messaging;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Iterator;
import java.util.LinkedList;

import crossbear.CertJudgment;

/**
 * A CertVerifyResult-message is sent in response to a CertVerifyRequest. It contains several CertJudgments which will be combined into a Report-String and a Rating which sums up the report in a single number.
 * 
 * The structure of the CertVerifyResult-message is
 * - Header
 * - Rating (one byte)
 * - Report about the certificate (String of variable length)
 * 
 * @author Thomas Riedmaier
 *
 */
public class CertVerifyResult extends Message {

	// List of all judgments that have been made on the certificate that was sent in the CertVerifyRequest-message for which this CertVerifyResult has been created.
	private LinkedList<CertJudgment> judgments = new LinkedList<CertJudgment>();

	/**
	 * Create a new Message of Type MESSAGE_TYPE_CERT_VERIFY_RESULT
	 */
	public CertVerifyResult(){
		super(Message.MESSAGE_TYPE_CERT_VERIFY_RESULT);
	}

	
	/**
	 * Adding a new judgment to the CertVerifyResult
	 * 
	 * @param judgment The judgment to add
	 */
	public void addJudgment(CertJudgment judgment){
		judgments.add(judgment);
	}
	
	/**
	 * Sum up all partial ratings of the judgments attached to this CertVerifyResult
	 * 
	 * @return The sum of the partial ratings cropped at 0 and 255
	 */
	public int getRating(){
		
		// Iterate over all judgments, get their ratings and sum them up
		int rating = 0;
		Iterator<CertJudgment> itr = judgments.iterator();
		while(itr.hasNext()){
			rating += itr.next().getRating();
		}
		
		// Crop the rating value to be non negative and less than 256 to fit into one byte
		if(rating<0) return 0;
		if(rating>255) return 255;
		
		return rating;
	}
	
	/**
	 * Combine all judgment texts into one report.
	 * 
	 * @return The concatenation of the judgments' textual representations.
	 */
	public String getReport() {

		//Iterate over all judgments, get their textual representations and concatenate them
		String re = "";
		for (int i = 0; i < judgments.size(); i++) {

			if (i != 0){
				re += '\n';
			}

			re += judgments.get(i).getText();
		}

		return re;
	}

	/* (non-Javadoc)
	 * @see crossbear.Message#writeContent(java.io.OutputStream)
	 */
	@Override
	protected void writeContent(OutputStream out) throws IOException {
	
		out.write(getRating()); //one byte for rating the result "as a number"
		
		out.write(getReport().getBytes());
		
	}
	
}
