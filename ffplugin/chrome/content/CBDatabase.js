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
 * This class implements a comfortable wrapper for Mozilla's SQLite-API. It provides both synchronous and asynchronous database access as well as prepared statements.
 * 
 * @param cbFrontend The cbFrontend-class that will be used to display information/errors to the user
 * 
 * @author Thomas Riedmaier
 */
Crossbear.CBDatabase = function (cbFrontend) {
	this.cbFrontend = cbFrontend;

	// Load the Firefox Components required to work with SQLite databases
	Components.utils.import("resource://gre/modules/Services.jsm");
	Components.utils.import("resource://gre/modules/FileUtils.jsm");

	// Open (and if not yet existing: create) the crossbear.sqlite database
	var file = FileUtils.getFile("ProfD", [ "crossbear.sqlite" ]);
	this.DBConn = Services.storage.openDatabase(file);

	// Create (if not yet existing) the performedTasks-table and its indices. This table will be used to store the information about when a HuntingTask was successfully executed using which PublicIP
	this.DBConn.executeSimpleSQL("CREATE TABLE IF NOT EXISTS performedTasks( ID INTEGER PRIMARY KEY ASC, TaskID INTEGER , PublicIP TEXT, ServerTimeOfExecution INTEGER);");
	this.DBConn.executeSimpleSQL("CREATE INDEX IF NOT EXISTS performedTasks_taskid_publicip ON performedTasks ( TaskID,PublicIP);");
	this.DBConn.executeSimpleSQL("CREATE INDEX IF NOT EXISTS performedTasks_taskid ON performedTasks ( TaskID);");

	// Create (if not yet existing) the certTrust-table aka the local TDC. Please note: "UNIQUE" induces a "INDEX" so there is no need to explicitly create it.
	this.DBConn.executeSimpleSQL("CREATE TABLE IF NOT EXISTS certTrust( ID INTEGER PRIMARY KEY ASC, CertHash TEXT, Host TEXT, Trust INTEGER , ValidUntil INTEGER, UNIQUE(CertHash, Host));");
	
	// Remove old entries from the local TDC
	this.DBConn.executeSimpleSQL("DELETE FROM certTrust WHERE ValidUntil < strftime('%s','now');");
	
	// "this" does not always point to THIS object (especially in callback functions). Therefore I use the "self" variable to hold a handle on THIS object
	var self = this;

	// Initialize the member function references for the class prototype (like this it's only done once and not every time a instance of this object is created)
	if (typeof (_cbdatabase_prototype_called) == 'undefined') {
		_cbdatabase_prototype_called = true;

		/**
		 * Execute a SQL-statement without using a prepared statement and without reading its result.
		 * 
		 * @param sqlStatement The SQL-statement to execute
		 */
		Crossbear.CBDatabase.prototype.executeSimple = function executeSimple(sqlStatement) {
			self.DBConn.executeSimpleSQL(sqlStatement);
		};

		/**
		 * Execute a SQL-statement in a synchronous way (i.e. wait until the database replies before returning from this function).
		 * 
		 * Please note: This function supports prepared statements with named parameters.
		 * 
		 * @param sqlStatement The SQL-statement to execute (e.g. "SELECT * FROM certTrust WHERE CertHsah = :hash")
		 * @param sqlParams An object holding the named parameters of the SQL-Statement (e.g. {'hash' : '1234567890ABCDEF'})
		 * @param expectedResultColumns An array containing all column-names of the result of the SQL-statement.
		 * @returns A 2D-array representing the result of the SQL-Statement. Accessing an entry can be done by result[rownumber].ColumnName
		 */
		Crossbear.CBDatabase.prototype.executeSynchronous = function executeSynchronous(sqlStatement, sqlParams, expectedResultColumns) {
			var stmt = null;
			var allrows = [];
			
			try {

				// Create a new mozIStorageStatement for the sqlStatement
				stmt = self.DBConn.createStatement(sqlStatement);

				// Bind all named parameters to the statement
				for ( var i in sqlParams) {
					stmt.bindByName(i, sqlParams[i]);
				}

				// Execute the statement and get one result row
				while (stmt.executeStep()) {

					/*
					 * Read the columns of the result row and copy their content into a blank object. This copy operation is necessary since the content of the result row itself is not available outside this function.
					 * 
					 * Copying the row's columns requires knowledge about the names of the columns. This is currently done by requiring the "expectedResultColumns"-parameter to be set by the user.
					 */ 
					var currentrow = new Object();
					for ( var i = 0; i < expectedResultColumns.length; i++) {
						currentrow[expectedResultColumns[i]] = stmt.row[expectedResultColumns[i]];
					}
					// Add the copy of the result row to the output
					allrows.push(currentrow);
				}

			} catch (e) {
				cbFrontend.displayTechnicalFailure("CBDatabase:executeSynchronous produced an error:  " + e, true);
			} finally {
				
				// Release the statement
				if (stmt != null) {
					stmt.reset();
				}
			}

			return allrows;
		};

		/**
		 * Execute a SQL-statement in a asynchronous way (i.e. return immediately from this function but pass a callback-function that will handle the result of the SQL-statement when it is available).
		 * 
		 * Please note: This function supports prepared statements with named parameters.
		 * 
		 * @param sqlStatement The SQL-statement to execute (e.g. "SELECT * FROM certTrust WHERE CertHsah = :hash")
		 * @param sqlParams An object holding the named parameters of the SQL-Statement (e.g. {'hash' : '1234567890ABCDEF'})
		 * @param callbackFunction The function that will receive an array of mozIStorageRows representing the result of the database query
		 */
		Crossbear.CBDatabase.prototype.executeAsynchronous = function executeAsynchronous(sqlStatement, sqlParams, callbackFunction) {
			try {
				var allrows = [];
				
				// Create a new mozIStorageStatement for the sqlStatement
				var stmt = self.DBConn.createStatement(sqlStatement);
				
				// Bind all named parameters to the statement
				for ( var i in sqlParams) {
					stmt.bindByName(i, sqlParams[i]);
				}

				// Execute the statement in an asynchronous way. Therefore define a handlers for the "there-is-more-data"-event, the "there-was-an-error"-event and the "asynchronous-execution-completed"-event
				stmt.executeAsync({
					
					// The handleResult-handler will be called when there is more data available from the result
					handleResult : function(aResultSet) {
						// Add the rows to the allrows-object which will finally be returned
						for ( var row = aResultSet.getNextRow(); row; row = aResultSet.getNextRow()) {
							allrows.push(row);
						}
					},

					// The handleError-handler will be called if there was an error
					handleError : function(aError) {
						cbFrontend.displayTechnicalFailure("CBDatabase:executeAsynchronous produced an error: " + aError.message, true);
					},

					// The handleCompletion-handler will be called when the execution of the query completed.
					handleCompletion : function(aReason) {
						
						// If it was aborted: Throw an exception
						if (aReason != Components.interfaces.mozIStorageStatementCallback.REASON_FINISHED) {
							cbFrontend.displayTechnicalFailure("CBDatabase:executeAsynchronous: Query canceled or aborted!", true);
						
						// If it completed successfully: Pass the accumulation of all returned result-rows to the callback function
						} else {
							if (callbackFunction != null) {
								callbackFunction(allrows);
							}
						}
					}
				});
			} catch (e) {
				cbFrontend.displayTechnicalFailure("CBDatabase:executeAsynchronous produced an error:  " + e, true);
			}
		};
	}
};