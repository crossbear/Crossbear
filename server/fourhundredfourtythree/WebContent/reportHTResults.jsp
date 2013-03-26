<%--

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

    Original authors: Thomas Riedmaier, Ralph Holz (TU München, Germany)

--%><%@ page import="crossbear.*,org.bouncycastle.jce.provider.BouncyCastleProvider,java.security.*,java.io.OutputStream"
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

	// Properties and settings of the Crossbear server
	private Properties properties;

	//Constructor-like functionality: Only performed the first time the page is loaded
	public void jspInit() {
		ServletContext sc = getServletContext();
		String contextPath = sc.getRealPath(File.separator);


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
			properties = new Properties(contextPath.concat("../../crossbear.properties"));

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
			Database db = new Database(properties.getProperty("database.url"),properties.getProperty("database.user"),properties.getProperty("database.password"));
			cm = new CertificateManager(db, 0, properties.getProperty("keystore.password"));
			db.close();


		} catch (Exception e) {

			Logger.dumpExceptionToFile(properties.getProperty("logging.dir")+"/fourhundredfourtythree.reportHTResult.init.error", e);

		}

	}
	%><%
	Database db = null;

	try {

		//Processing the Hunting Task Result is quite lenghty. Therefore i moved this functionality to the "Hunting Task Result Processor " (HTRProcessor)
		db = new Database(properties.getProperty("database.url"),properties.getProperty("database.user"),properties.getProperty("database.password"));
		HTRProcessor htrp = new HTRProcessor(request.getInputStream(), cm, db);
		

	} catch (Exception e) {	
		/*
		* None of the calls above catches exceptions. Whenever something went wrong (e.g. with decoding the client's request)
		* A exception is thrown and cought here. Since it's not very smart to tell attackers what went wrong a dummy reply is sent to them.
		*/

		// For debugging reasons: Log what went wrong
		Logger.dumpExceptionToFile(properties.getProperty("logging.dir")+"/fourhundredfourtythree.reportHTResult.processing.error", e);

	} finally {
		if (db != null)
			db.close();
	}
%>
