<%@ page trimDirectiveWhitespaces="true" %>
<%@ page import="java.io.File, java.io.OutputStream, java.io.FileInputStream, java.util.logging.*" language="java" contentType="text/plain; charset=UTF-8" %>

<%
Logger log = Logger.getLogger(getClass().getName());

OutputStream os = response.getOutputStream();
String country = request.getParameter("country");
if (country == null) {
    country = "DEFAULT";
}

country = country.toUpperCase();

String countrypath = getServletContext().getRealPath("Protector-" + country + ".list");
String defaultpath = getServletContext().getRealPath("Protector-DEFAULT.list");

File f = new File(countrypath);

if (!f.exists() || f.isDirectory() || !f.canRead()) {
    log.log(Level.WARNING, String.format("Country URL file %s could not be read, reading default list.", countrypath));
    f = new File(defaultpath);
    if (!f.exists() || f.isDirectory() || !f.canRead()) {
	log.log(Level.SEVERE, String.format("Could not access default list %s.", defaultpath));
	return;
    }
}
FileInputStream fin = new FileInputStream(f);
// Read file and copy to output stream.
byte[] buf = new byte[4096];
while (true) {
    int r = fin.read(buf);
    if (r == -1) {
	break;
    }
    os.write(buf, 0, r);
}
%>
