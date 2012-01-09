<%--
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

--%>
<%@ page import="crossbear.*,org.bouncycastle.jce.provider.BouncyCastleProvider,java.security.*,java.io.OutputStream"
	language="java" 
	contentType="application/octet-stream"
%><%!

	/*
	* reportHTResults.jsp takes as input a Sequence of HuntingTaskReply-messages. It checks if they are valid and - in case they are -
	* stores them in the database. It doesn't have any meaningful output.
	*/

	/* 
	* The CertificateManager loads all certificates from the local keystore in order to be able to calculate as many
	* certificate chains as possible. Doing so takes some time and is therefore only done once in jspInit. To use the loaded
	* keys every time verifyCert.jsp a global CertificateManager object is created.
	*/
	private CertificateManager cm;

	//Constructor-like functionality: Only performed the first time the page is loaded
	public void jspInit() {

		try {
			
			/*
			* Adding the bouncy castle Security Provider is required for the use of 
			* - "SHA256"-HMAC
			* - "AES/CBC/PKCS7Padding"-Symmetric Encryption
			* - "RSA/None/OAEPWithSHA1AndMGF1Padding"-Asymmetric Encryption
			* all of these are used in Crossbear.
			*/
			Security.addProvider(new BouncyCastleProvider());

			/*
			* Like mentioned above the CertificateManager needs to load the local keystore on initilization.
			* This is done here.
			* 
			* In order to be able to look into all certificates that are part of any certificate chain these
			* certificates need to be put in the database also. This requires a database object.
			*
			* Since Crossbear uses Transactions there is no such thing as a global Database object. That again is
			* the reason why a new database connection is created to insert the certificates and closed afterwards.
			*/
			Database db = new Database();
			cm = new CertificateManager(db,0);
			db.close();


		} catch (Exception e) {

			Logger.dumpExceptionToFile("/var/lib/tomcat6/webapps/fourhundredfourtythree/init.reportHTResult.error", e);

		}

	}
	%><%
	// Crossbear works on binary messages. To send these from the server to the client they need to be written into response.getOutputStream()
	OutputStream outStream = response.getOutputStream();
	Database db = null;

	try {

		//Processing the Hunting Task Result is quite lenghty. Therefore i moved this functionality to the "Hunting Task Result Processor " (HTRProcessor)
		db = new Database();
		HTRProcessor htrp = new HTRProcessor(request.getInputStream(), cm, db);

	} catch (Exception e) {	
		/*
		* None of the calls above catches exceptions. Whenever something went wrong (e.g. with decoding the client's request)
		* A exception is thrown and cought here.
		*/

		// For debugging reasons: Log what went wrong
		Logger.dumpExceptionToFile("/var/lib/tomcat6/webapps/fourhundredfourtythree/processing.reportHTResult.error", e);

	} finally {
		/*
		* Since it's not very smart to tell attackers if something went wrong a dummy reply is sent to them.
		*/
		outStream.write(new String("Crossbear").getBytes());
		
		if (db != null)
			db.close();
	}

	// Finally: Sent the reply to the client
	response.flushBuffer();
%>