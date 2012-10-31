/*
Copyright (c) 2011, Thomas Riedmaier, Technische Universität München
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of Crossbear nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THOMAS RIEDMAIER BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

package crossbear;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Security;
import java.sql.SQLException;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import crossbear.Properties;
import crossbear.messaging.FpVerifyRequest;

/**
* VerifyFp takes as input an FpVerifyRequest message. It is checked if the request is valid (i.e. syntactically speaking).
* Processing roughly consists of the following steps:
* - parse FpVerifyRequest message, check if it is well formed and extract requested data
* - check if requested fingerprint is in database
* - if not in database or if entry is not recent enough, potentially make an online ssh-keyscan
* - compare host key fingerprint from database/online fetch to fingerprint send by client 
* - build and send response
* 
* @author Thomas Riedmaier
* @author Oliver Gasser
* 
*/
@WebServlet("/VerifyFp")
public class VerifyFp extends HttpServlet {
	private static final long serialVersionUID = 1L;	

	// Properties and settings of the Crossbear server
	private Properties properties;

    @Override
    public void init() throws ServletException {
    	super.init();
    	
    	try {			
			/*
			* Adding the bouncy castle Security Provider is required for the use of 
			* - "SHA256"-HMAC
			* - "AES/CBC/PKCS7Padding"-Symmetric Encryption
			* - "RSA/None/OAEPWithSHA1AndMGF1Padding"-Asymmetric Encryption
			* all of these are used in Crossbear.
			*/
			Security.addProvider(new BouncyCastleProvider());
					
			// Load the porperties and settings from the config file
			properties = new Properties("/opt/apache-tomcat/webapps/crossbear.properties");
		} catch (Exception e) {
			Logger.dumpExceptionToFile(properties.getProperty("logging.dir")+"/fourhundredfourtythree.verifyFp.init.error", e);
		}
    }

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
		// Response is a binary message
		response.setContentType("application/octet-stream");
		
		Database db = null;
		OutputStream outStream = null;
		
		try {
			// To send binary messages from the server to the client they need to be written into response.getOutputStream()
			outStream = response.getOutputStream();
			
			// First of all try to decode the FpVerifyRequest sent by the client
			FpVerifyRequest fpvr = FpVerifyRequest.readFromStream(request.getInputStream(), request.getRemoteAddr(), request.getLocalAddr());
			
			// If the decoding succeeded open a database connection and create a FpVRProcessor
			db = new Database(properties.getProperty("database.url"), properties.getProperty("database.user"), properties.getProperty("database.password"));
			FpVRProcessor fpvrp = new FpVRProcessor(fpvr, db);
			
			// Process request and write result
			outStream.write(fpvrp.process().getBytes());
		} catch (Exception e) {
			/*
			* None of the calls above catches exceptions. Whenever something went wrong (e.g. with decoding the client's request)
			* an exception is thrown and caught here. Since it's not very smart to tell attackers what went wrong a dummy reply is sent to them.
			*/

			// For debugging reasons: Log what went wrong
			Logger.dumpExceptionToFile(properties.getProperty("logging.dir")+"/fourhundredfourtythree.verifyFp.processing.error", e);
		} finally {
			// Cleanup
			if (db != null) {
				try {
					db.close();
				} catch (SQLException e) {
					Logger.dumpExceptionToFile(properties.getProperty("logging.dir")+"/fourhundredfourtythree.verifyFp.processing.error", e);
				}
			}
			outStream.flush();
			outStream.close();
		}
	}
}
