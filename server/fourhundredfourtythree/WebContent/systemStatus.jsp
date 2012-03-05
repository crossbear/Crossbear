<%@ page import="crossbear.*" language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%><%!

	/*
	* systemStatus.jsp does not expect any input and displays an HTML page that visualizes the current status of the Crossbear system.
	*/
	
	// Properties and settings of the Crossbear server
	private Properties properties;

	//Constructor-like functionality: Only performed the first time the page is loaded
	public void jspInit() {

		try {
					
			// Load the porperties and settings from the config file
			properties = new Properties("/opt/apache-tomcat/webapps/crossbear.properties");

		} catch (Exception e) {

			Logger.dumpExceptionToFile(properties.getProperty("logging.dir")+"/fourhundredfourtythree.systemStatus.init.error", e);
		}
	}
	%><!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>Current Status Of The Crossbear System</title>
</head>
<body>

<%

Database db = null;

try {

	// open a database connection
	db = new Database(properties.getProperty("database.url"),properties.getProperty("database.user"),properties.getProperty("database.password"));

	// get the status of the crossbear system and display its HTML encoded representation
	out.println(SystemStatus.getStatusHTML(db));

} catch (Exception e) {
	/*
	* None of the calls above catches exceptions. Whenever something went wrong (e.g. when accessing the database)
	* an exception is thrown and cought here. Since it's not very smart to tell attackers what went wrong a dummy reply is sent to them.
	*/

	// For debugging reasons: Log what went wrong
	Logger.dumpExceptionToFile(properties.getProperty("logging.dir")+"/fourhundredfourtythree.systemStatus.processing.error", e);

} finally {
	if (db != null)
		db.close();
}

%>

</body>
</html>