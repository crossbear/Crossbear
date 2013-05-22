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
 * This dialog displays the user's local TDC and opens a EditTDCEntryDlg when a user clicked on an entry of the cache
 */

// A list of criteria that can be chosen to order the entries of the TDC (Fixed lists prevents SQL-Injection)
var orderByConstants = {
	Hash : "CertHash",
	Host : "Host",
	Trust : "Trust",
	ValidUntil : "VU"
};

// A struct meant to convert a boolean into a SQL-ordering. The way to use it: orderAscending[asc?1:0]; 
var orderAscending = [
	 " DESC",
	 " ASC"
];

// Flag indicating whether to order the entries in the dialog's ListBox in an ascending order or not
var asc = true;

// Criterion that is used to order the entries in the dialog's ListBox
var orderBy = orderByConstants.Host;

/**
 * Take an array of mozIStorageRows, each representing an entry in the TDC, and place it in the dialog's ListBox.
 * 
 * @param allrows The array of mozIStorageRows.
 */
function displayTrustDecisions(allrows){
	
	// Get a handle to the dialog's ListBox
	var certList = document.getElementById('crossbear-certList');
	
	// Clear the ListBox (i.e. remove all of its elements)
	while(certList.itemCount >0){
		certList.removeItemAt(0);
	}
	
	// Iterate over all elements of "allrows" and create an entry in the ListBox for each of them
	for (var i = 0; i < allrows.length; i++)
	    {
			// Create a new row for the ListBox
	        var row = document.createElement('listitem');
	        
	        // Set the row's ID
	        row.id = allrows[i].getResultByName("ID");
	        
	        // Add a cell to the row containing the entry's Host
	        var cell = document.createElement('listcell');
	        cell.setAttribute('label', allrows[i].getResultByName("Host"));
	        row.appendChild(cell);

	        // Add a cell to the row containing the entry's CertHash
	        cell = document.createElement('listcell');
	        cell.setAttribute('label',  allrows[i].getResultByName("CertHash") );
	        row.appendChild(cell);
	        
	        // Add a cell to the row containing the entry's Validity
	        cell = document.createElement('listcell');
	        cell.setAttribute('label',  allrows[i].getResultByName("VU") );
	        row.appendChild(cell);
	        
	        // Add a cell to the row containing the entry's Trust
	        cell = document.createElement('listcell');
	        cell.setAttribute('label',  (allrows[i].getResultByName("Trust")==1)?"X":"" );
	        cell.setAttribute('style',  "text-align:center" );
	        row.appendChild(cell);

	        // Add the new row to the ListBox
	        certList.appendChild(row);
	    }
}

/**
 * Request the content of the local TDC from the database using displayTrustDecisions as callback-function (i.e. displayTrustDecisions will handle the database reply containing the cache entries)
 */
function loadTrustDecisionsFromDatabase(){
	
	// Build the SQL-Statement to request the content of the TDC ...
	var sqlStatement = "SELECT ID, Host, CertHash, datetime(ValidUntil, 'unixepoch', 'localtime') AS VU, Trust FROM certTrust ORDER BY "+orderBy+orderAscending[asc?1:0];
	var params = new Object();
	
	// ... and execute it.
	window.arguments[0].inn.cbFrontend.cbdatabase.executeAsynchronous(sqlStatement,params,displayTrustDecisions);
}

/**
 * Initialization function (called once when the dialog is about to display)
 */
function onLoad() {
	// Fill the dialog's ListBox with data
	loadTrustDecisionsFromDatabase();
}

/**
 * Close the dialog
 * 
 * @returns true (So the dialog will be closed)
 */
function ok() {
	return true;
}
