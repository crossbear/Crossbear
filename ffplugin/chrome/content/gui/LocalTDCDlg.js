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
 * This dialog displays the user's local certificate cache and opens a EditCertificateCacheEntryDlg when a user clicked on an entry of the cache
 */

// A list of criteria that can be chosen to order the entries of the certificate cache (Fixed lists prevents SQL-Injection)
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
 * Take an array of mozIStorageRows, each representing an entry in the certificate cache, and place it in the dialog's ListBox.
 * 
 * @param allrows The array of mozIStorageRows.
 */
function displayCertificates(allrows){
	
	// Get a handle to the dialog's ListBox
	var certList = document.getElementById('certList');
	
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
 * Request the content of the local certificate cache from the database using displayCertificates as callback-function (i.e. displayCertificates will handle the database reply containing the cache entries)
 */
function loadCertificatesFromDatabase(){
	
	// Build the SQL-Statement to request the content of the certificate cache ...
	var sqlStatement = "SELECT ID, Host, CertHash, datetime(ValidUntil, 'unixepoch', 'localtime') AS VU, Trust FROM certTrust ORDER BY "+orderBy+orderAscending[asc?1:0];
	var params = new Object();
	
	// ... and execute it.
	window.arguments[0].inn.cbFrontend.cbdatabase.executeAsynchronous(sqlStatement,params,displayCertificates);
}

/**
 * Initialization function (called once when the dialog is about to display)
 */
function onLoad() {
	// Fill the dialog's ListBox with data
	loadCertificatesFromDatabase();
}

/**
 * Close the dialog
 * 
 * @returns true (So the dialog will be closed)
 */
function ok() {
	return true;
}