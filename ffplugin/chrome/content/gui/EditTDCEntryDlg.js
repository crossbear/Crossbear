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
*/

/**
 * This dialog is a GUI for the user to modify an entry of the local TDC
 */

/**
 * Initialization function (called once when the dialog is about to display)
 */
function onLoad() {
	
	// Build a statement that loads a single entry from the local TDC ...
	var sqlStatement = "SELECT CertHash, Host, Trust, datetime(ValidUntil, 'unixepoch', 'localtime') AS VU FROM certTrust WHERE ID = :id";
	var params = new Object();
	params['id'] = window.arguments[0].inn.selectedID;

	// ... and execute it.
	var expectedRows = [ "CertHash", "Host", "Trust", "VU" ];
	var databaseEntry = window.arguments[0].inn.cbFrontend.cbdatabase.executeSynchronous(sqlStatement, params, expectedRows);

	// Put the data that was returned by the SQL-statement into the GUI-elements meant to display it:
	document.getElementById("crossbear-ce-host").value = databaseEntry[0].Host;

	document.getElementById("crossbear-ce-hash").value = databaseEntry[0].CertHash;

	document.getElementById("crossbear-ce-valid-until").value = databaseEntry[0].VU;

	if (databaseEntry[0].Trust == 1) {
		document.getElementById("crossbear-ce-trust").selectedIndex = 0;
	} else {
		document.getElementById("crossbear-ce-trust").selectedIndex = 1;
	}
}

/**
 * Remove an entry from the TDC and close the dialog
 */
function removeEntry() {
	// Get the "hostname"/"certificate"-combination whose entry should be removed from the cache ...
	var hash = document.getElementById("crossbear-ce-hash").value;
	var host = document.getElementById("crossbear-ce-host").value;
	
	// ... remove it from the cache ...
	window.arguments[0].inn.cbFrontend.cbtrustdecisioncache.remove(hash, host);
	
	// ... and close the dialog.
	window.close();
}

/**
 * Read the changes the user made from the GUI-elements and update the TDC entry.
 * 
 * @returns true (So the dialog will be closed) if everything went fine and false if the user entered invalid data.
 */
function accept() {
	// Get the "hostname"/"certificate"-combination for which the entry should be changed
	var hash = document.getElementById("crossbear-ce-hash").value;
	var host = document.getElementById("crossbear-ce-host").value;
	
	// Get the new Trust-value for that combination
	var trust = document.getElementById("crossbear-ce-trust-yes").selected;
	
	// Read the new "valid-until"-date from the GUI. It should have the format YYYY-MM-DD HH:MM:SS.
	var dateTime = document.getElementById("crossbear-ce-valid-until").value.split(" ");
	
	// Therefore there should be two parts when it is split up at the " "-char
	if (dateTime.length != 2){
		// If not -> don't accept the user input
		return false;
	}

	// The left part should consist of three "-"-separated numbers
	var date = dateTime[0].split("-");
	if (date.length != 3){
		// If not -> don't accept the user input
		return false;
	}

	// The right part should consist of three ":"-separated numbers
	var time = dateTime[1].split(":");
	if (time.length != 3){
		// If not -> don't accept the user input
		return false;
	}
	
	// Make sure that all of the dateTime-elements are numbers
	if(!Crossbear.isNumber(date[0]) || !Crossbear.isNumber(date[1]) || !Crossbear.isNumber(date[2]) ||
			!Crossbear.isNumber(time[0]) || !Crossbear.isNumber(time[1]) || !Crossbear.isNumber(time[2])){
		return false;
	}

	try {
		// Try to build a "Date"-object based on the user's input
		var validUntil = new Date();
		validUntil.setFullYear(date[0], date[1] - 1, date[2]);
		validUntil.setHours(time[0], time[1], time[2], 0);
	} catch (e) {
		// If that failed: don't accept the user's input
		window.arguments[0].inn.cbFrontend.displayTechnicalFailure("EditTDC:accept: could not parse date.", false);
		return false;
	}

	// If everything went fine until here then the user's input seems to be valid: Update the TDC entry by overwriting the old one
	window.arguments[0].inn.cbFrontend.cbtrustdecisioncache.add(hash, host, trust, Math.round(validUntil.getTime() / 1000));
	return true;
}

/**
 * Close the dialog without modifying the cache entry
 * 
 * @returns true (So the dialog will be closed)
 */
function cancel() {
	return true;
}
