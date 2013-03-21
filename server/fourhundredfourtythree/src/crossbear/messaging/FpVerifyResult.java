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

package crossbear.messaging;

import java.io.IOException;
import java.io.OutputStream;

/**
 * A FpVerifyResult message is sent in response to a FpVerifyRequest. It contains the result of the fingerprint verification process in a single byte.
 * 
 * The structure of the CertVerifyResult-message is
 * - Header
 * - Message format version (1 byte)
 * - Result of verify request (1 byte)
 * 
 * @author Thomas Riedmaier
 * @author Oliver Gasser
 *
 */
public class FpVerifyResult extends Message {

	/////////////////////////////////////////////////
	// MESSAGE_TYPE_FP_VERIFY_RESULT format:       //
	/////////////////////////////////////////////////
	// | T | L | V | R |                           //
	/////////////////////////////////////////////////
	// T  = Message type (1 Byte) = 60             //
	// L  = Message length in bytes (2 Bytes)      //
	// V  = Message format version (1 Byte) = 1    //
	// R  = Result of verify request (1 Byte)      //
	/////////////////////////////////////////////////
	
	// Enum specifying the possible results for the fingerprint verification
	public enum FpVerifyResults {
		MATCH,
		NO_MATCH,
		NO_ENTRY
	};
	
	// The format version of the FpVerifyRequest message
	private static final byte MESSAGE_TYPE_FP_VERIFY_RESULT_FORMAT_VERSION = 1;
	
	// The result of the fingerprint verification
	private FpVerifyResults result;
	
	/**
	 * Create a new Message of Type MESSAGE_TYPE_FP_VERIFY_RESULT
	 */
	public FpVerifyResult(){
		super(Message.MESSAGE_TYPE_FP_VERIFY_RESULT);
	}
	
	/**
	 * @param result the result which will be set for this message
	 */
	public void setResult(FpVerifyResults result) {
		this.result = result;
	}

	/* (non-Javadoc)
	 * @see crossbear.Message#writeContent(java.io.OutputStream)
	 */
	@Override
	protected void writeContent(OutputStream out) throws MessageSerializationException {
	
		if (this.result == null) {
			throw new RuntimeException("Result for message was not set.");
		}
		try {
		    out.write(MESSAGE_TYPE_FP_VERIFY_RESULT_FORMAT_VERSION);
		
		    out.write((byte) this.result.ordinal());
		} catch (IOException e) {
		    throw new MessageSerializationException("Could not write to output stream", e);
		}
	}	
}
