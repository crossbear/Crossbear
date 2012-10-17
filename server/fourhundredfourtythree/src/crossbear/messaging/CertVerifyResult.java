/*
 * Copyright (c) 2011, Thomas Riedmaier, TU MÃ¼nchen
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
