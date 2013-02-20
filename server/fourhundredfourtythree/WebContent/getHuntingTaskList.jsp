<%--
Copyright (c) 2011, Thomas Riedmaier, Technische Universit�t M�nchen
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

--%><%@ page import="crossbear.*,crossbear.messaging.*,org.bouncycastle.jce.provider.BouncyCastleProvider,java.security.*,java.io.OutputStream,java.net.InetAddress"
	language="java" 
	contentType="application/octet-stream"
%><%!

	/*
	* getHuntingTaskList.jsp doesn't take any input parameters and returns a list of all currently active Hunting Tasks
	* (Sequence of HuntingTask-messages) combined with a PublicIPNotification-message and a CurrentServerTime-message
	*/

	/*
	* The Crossbear server uses several caches to speed up requests processing:
	* - CertificateCache (contains the certificates that were recently observed by the server)
	* - CertVerifyResultCache (contains the results that were generated by this page in case they are requested multiple times)
	* - HuntingTaskListCache (contains the current list of hunting tasks)
	*
	* cacheValidity is the time in milliseconds that an entry stays valid in one of those caches
	*
	* SUGG: The cacheValidity could be adjusted dynamically based on the server's current load
	*/
	private int cacheValidity = 5 * 60 * 1000;
	
	// Properties and settings of the Crossbear server
	private Properties properties;

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
					
			// Load the porperties and settings from the config file
			properties = new Properties("/opt/apache-tomcat/webapps/crossbear.properties");

		} catch (Exception e) {

			Logger.dumpExceptionToFile(properties.getProperty("logging.dir")+"/fourhundredfourtythree.getHuntingTaskList.init.error", e);
		}
	}
	%><%
	Database db = null;

	try {
		// Crossbear works on binary messages. To send these from the server to the client they need to be written into response.getOutputStream()
		OutputStream outStream = response.getOutputStream();

		db = new Database(properties.getProperty("database.url"),properties.getProperty("database.user"),properties.getProperty("database.password"));

		/*
		* The hunting task list consists of three parts:
		* - The actual hunting task list (which might be freshly calculated or just read from cache)
		* - A notification for the client which public IP he/she uses (safes a roundrip time since getPublicIP.jsp needs to be called one time less)
		* - The current server time (required since all timestamps in the hunting task replies will be in server time and not in local system time)
		* 
		* It is assembled here.
		*/
		InetAddress remoteIP = InetAddress.getByName(request.getRemoteAddr());
		MessageList reply = MessageList.getCurrentHuntingTaskList(remoteIP, cacheValidity, db);
		reply.add(new PublicIPNotification(remoteIP, db));
		reply.add(new CurrentServerTime());

		//Send the Hunting Task List to the client
		outStream.write(reply.getBytes());
		
		// Finally: Sent the reply to the client
		response.flushBuffer();

	} catch (Exception e) {
		/*
		* None of the calls above catches exceptions. Whenever something went wrong (e.g. with decoding the client's request)
		* A exception is thrown and cought here. Since it's not very smart to tell attackers what went wrong a dummy reply is sent to them.
		*/

		// For debugging reasons: Log what went wrong
		Logger.dumpExceptionToFile(properties.getProperty("logging.dir")+"/fourhundredfourtythree.getHuntingTaskList.processing.error", e);

	} finally {
		if (db != null)
			db.close();
	}
%>