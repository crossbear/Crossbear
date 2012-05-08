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