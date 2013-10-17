<%@ page
	import="crossbear.*,crossbear.messaging.*,org.bouncycastle.jce.provider.BouncyCastleProvider,java.security.*,java.io.*"
	language="java"
	contentType="application/octet-stream" %><%!
/*    This file is part of Crossbear.

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
	/*
	* getPublicIP.jsp is - unlike all other pages - meant to be accessed over plain http. This is necessary since it's not possible to acces
	* a server over https using it's ip, which in turn needs to be done since the desired output of this page is an PublicIP of a certain version.
	* 
	* getPublicIP.jsp takes as input a PublicIPNotifRequest-Message which contains a RSA-encrypted AES key, exctracts the latter, generates a
	* PublicIPNotification-message and encrypts it with the AES key. The generated crypto text is then sent back to the client.
	*/
	
	/*
	* Since the loading of the RSA key from file takes some time it is therefore only done once in jspInit. To use it
	* every time getPublicIP.jsp is loaded a global PublicIPNotifProcessor object is created.
	*/
	private PublicIPNotifProcessor pipnp;
	
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
			ServletContext sc = getServletContext();
			String contextPath = sc.getRealPath(File.separator);


			Security.addProvider(new BouncyCastleProvider());

			// Load the porperties and settings from the config file
			properties = new Properties(contextPath.concat("../../crossbear.properties"));
					
			/*
			* Like mentioned above the PublicIPNotifProcessor needs to load the RSA key on initilization.
			* This is done here.
			*/
			pipnp = new PublicIPNotifProcessor(properties.getProperty("pkey.keyStoreFile"),properties.getProperty("pkey.keyStorePassword"),properties.getProperty("pkey.alias"),properties.getProperty("pkey.password"));

		} catch (Exception e) {

			Logger.dumpExceptionToFile(properties.getProperty("logging.dir")+"/eighty.getPublicIP.init.error", e);
		}
	}
	%><%
	Database db = null;
	
	try {
		
		// Crossbear works on binary messages. To send these from the server to the client they need to be written into response.getOutputStream()
		OutputStream outStream = response.getOutputStream();
				
		//First of all try to decode the PublicIPNotifRequest sent by the client
		PublicIPNotifRequest pipnr = PublicIPNotifRequest.readFromStream(request.getInputStream(), request.getRemoteAddr());
		
		
		// Open a database connection
		db = new Database(properties.getProperty("database.url"),properties.getProperty("database.user"),properties.getProperty("database.password"));
		
		// Decrypt the AES-key, generate a PublicIPNotification-message and encrypt it with the AES-key
		byte[] reply = pipnp.generateEncryptedPublicIPNotif(pipnr,db);

		// Send the result to the client
		outStream.write(reply);
				
		// Finally: Sent the reply to the client (flush the buffer)
		response.flushBuffer();

	} catch (Exception e) {
		/*
		* None of the calls above catches exceptions. Whenever something went wrong (e.g. with decoding the client's request)
		* A exception is thrown and cought here. Since it's not very smart to tell attackers what went wrong a dummy reply is sent to them.
		*/
		
		// For debugging reasons: Log what went wrong
		Logger.dumpExceptionToFile(properties.getProperty("logging.dir")+"/eighty.getPublicIP.processing.error", e);
			
	} finally {
		if (db != null)
			db.close();
	}
%>