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
 * This class bundles all functionality that is related to
 * - Displaying information/warnings to the user
 * - Getting and setting the user's preferences 
 * - (de-)activation of the Hunter/Guard
 * - System initialization and shutdown
 * 
 * @param cbServerName The Hostname of the Crossbear server (e.g. otranto.net.in.tum.de)
 * 
 * @author Thomas Riedmaier
 */
function CBFrontend(cbServerName) {

	// The Hostname of the Crossbear server
	this.cbServerName = cbServerName;
	
	// The difference between the local time and the Crossbear server time: cbServerTimeDiff = cbServerTime-localTime
	this.cbServerTimeDiff = 'undefined';
	
	// Remembers if a shutdown was requested (required in order not to do deinitialization twice). If this is set to true the loop inside the "UnknownCertDlg" will quit
	this.shutdownWasRequested = false;

	// Initialize the rest of the Crossbear system (if possible)
	this.cbdatabase = new CBDatabase(this);
	this.cbnet = new CBNet(this);
	this.cbhunter = new CBHunter(this);
	this.cbguard = new CBGuard(this);
	this.cbhtlprocessor = new CBHTLProcessor(this);
	this.cbcertificatecache = new CBCertificateCache(this);
	this.cbeventobserver = new CBEventObserver(this);

	// Some elements require functions from CBFrontend and will therefore initialized below.
	this.TaskPullTimer = null;
	this.ServerRSAKeyPair = null;
	
	// Open Firefox components related to logging into the Console and Accessing User-Preferences
	var consoleService = Components.classes["@mozilla.org/consoleservice;1"].getService(Components.interfaces.nsIConsoleService);
	var prefs = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefService).getBranch("crossbear.");
	var defPrefs = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefService).getDefaultBranch("crossbear.");
	
	// Initialize the member function references for the class prototype (like this it's only done once and not every time a instance of this object is created)
	if (typeof (_cbfrontend_prototype_called) == 'undefined') {
		_cbfrontend_prototype_called = true;

		/**
		 * Display an exception caused by a technical failure
		 * 
		 * @param what The message that should be displayed
		 * @param critical If True Crossbear will be shut down after the displaying the exception
		 */
		CBFrontend.prototype.displayTechnicalFailure = function displayTechnicalFailure(what, critical) {
			
			// Display the message of the failure in the "Error"-tab of the Error Console
			Components.utils.reportError(what);
			
			// If the exception was a critical one: Shutdown the system ...
			if (critical) {
				this.shutdown(true);
				
				// ... display a Message-Box so the user is aware that something went wrong
				var crashText = "Crossbear just crashed :(\n It is very sorry for the inconvenience.";
				alert(crashText);
				
				// .. and finally crash ;)
				throw crashText;
			}

		};

		/**
		 * Get an estimation of the current local time of the Crossbear server
		 * @returns A timestamp that is an estimation of the current local time of the Crossbear server
		 */
		CBFrontend.prototype.getServerTime = function getServerTime() {
			
			// Check if the difference between the local time and the Crossbear server time is known
			if(this.cbServerTimeDiff != 'undefined'){
				// If yes: use it to estimate the current local time of the Crossbear server (by adding it to the current local time)
				return Math.round(new Date().getTime() / 1000) + this.cbServerTimeDiff;
			
			}
			else{
				// if not: throw an exception
				this.displayTechnicalFailure("CBFrontend:getServerTime: Server time is not known but was requested", true);
			}
		};
		
		/**
		 * Calculate the difference between the local time and the time at the Crossbear server. Store it in the cbServerTimeDiff-variable afterwards.
		 * 
		 * Please note: cbServerTimeDiff = currentServerTime - currentLocalTime
		 * 
		 * @param currentServerTime A timestamp of the current local time of the Crossbear server
		 */
		CBFrontend.prototype.calcAndStoreCbServerTimeDiff = function calcAndStoreCbServerTimeDiff(currentServerTime) {
			this.cbServerTimeDiff = currentServerTime-Math.round(new Date().getTime() / 1000);
		};
		
		/**
		 * Display an information to the user. This is currently done by writing into the "Information"-tab of the Error Console
		 * 
		 * @param what The message to display
		 */
		CBFrontend.prototype.displayInformation = function displayInformation(what) {
			// Alternative for the line below: console.log
			consoleService.logStringMessage(what);
		};

		/**
		 * Warn the user that system might currently be under attack. This is currently done by displaying a WarnUserDlg
		 * 
		 * @param thread The message explaining the thread that the user is supposingly facing
		 * @param timeoutSec A Timeout parameter specifying how long the warning is minimally displayed
		 */
		CBFrontend.prototype.warnUserAboutBeingUnderAttack = function warnUserAboutBeingUnderAttack(thread, timeoutSec) {

			// Build an object containing the parameters for the WarnUserDlg
			var params = {
				inn : {
					thread : thread,
					timeoutSec : timeoutSec
				},
				out : {}
			};

			// Open the Dialog
			window.openDialog("chrome://crossbear/content/gui/WarnUserDlg.xul", "Crossbear - Warning you about a security Thread", "chrome,centerscreen,dependent=YES,dialog=YES,modal=YES,close=no", params);
		};

		/**
		 * Get the default value of a Crossbear preference
		 * 
		 * Please note: Javascript uses different functions depending on what type a preference has. Therefore the type needs to be specified.
		 * 
		 * @param name The name of the Preference
		 * @param type The type of the Preference ("bool", "int", "string")
		 * @returns The default value of type "type" of the Crossbear preference with name "name"
		 */
		CBFrontend.prototype.getDefaultPref = function getDefaultPref(name, type) {
			try {
				// Read the preference according to its type and return it
				if (type.startsWith("bool")) {
					return defPrefs.getBoolPref(name);
				} else if (type.startsWith("int")) {
					return defPrefs.getIntPref(name);
				} else {
					return defPrefs.getCharPref(name);
				}
			} catch (e) {
				this.displayTechnicalFailure("CBFrontend:getDefaultPref: An error occured while querying "+name+"("+type+"): " + e, true);
			}
		};

		/**
		 * Get the user defined value of a Crossbear preference
		 * 
		 * Please note: Javascript uses different functions depending on what type a preference has. Therefore the type needs to be specified.
		 * 
		 * @param name The name of the Preference
		 * @param type The type of the Preference ("bool", "int", "string")
		 * @returns The user defined value of type "type" of the Crossbear preference with name "name"
		 */
		CBFrontend.prototype.getUserPref = function getUserPref(name, type) {
			try {
				// Read the preference according to its type and return it
				if (type.startsWith("bool")) {
					return prefs.getBoolPref(name);
				} else if (type.startsWith("int")) {
					return prefs.getIntPref(name);
				} else {
					return prefs.getCharPref(name);
				}
			} catch (e) {
				this.displayTechnicalFailure("CBFrontend:getUserPref: An error occured while querying "+name+"("+type+"): " + e, true);
			}
		};

		/**
		 * Set the value of a Crossbear preference
		 * 
		 * Please note: Javascript uses different functions depending on what type a preference has. Therefore the type needs to be specified.
		 * 
		 * @param name The name of the Preference
		 * @param type The type of the Preference ("bool", "int", "string")
		 * @param value The new value of the Preference
		 */
		CBFrontend.prototype.setUserPref = function setUserPref(name, type, value) {
			try {
				// Set the preference according to its type
				if (type.startsWith("bool")) {
					prefs.setBoolPref(name, value);
				} else if (type.startsWith("int")) {
					prefs.setIntPref(name, value);
				} else {
					prefs.setCharPref(name, value);
				}
			} catch (e) {
				this.displayTechnicalFailure("CBFrontend:setUserPref: An error occured while setting "+name+"("+type+") to "+value+": " + e, true);
			}
		};

		/**
		 * Shutdown Crossbear
		 * 
		 * @param systemCrashed Flag indicating if the system performs a normal shutdown or if it crashed.
		 */
		CBFrontend.prototype.shutdown = function shutdown(systemCrashed) {
			
			// Only shut down if the system is active
			if(!this.shutdownWasRequested){
				
				// Mark the system as inactive (so the shutdown is not performed twice)
				this.shutdownWasRequested = true;
				
				// Deactivate the Guard
				this.deactivateGuard(systemCrashed);
				
				// Perform a clean shutdown of the Guard
				this.cbeventobserver.shutdownGuard();
				
				// Deactivate the Hunter
				this.deactivateHunter(systemCrashed);
				
				// Terminate any running HuntingTasks
				this.cbhunter.terminate();

			}

		};
		
		/**
		 * Enable Crossbear's Hunting-functionality
		 */
		CBFrontend.prototype.activateHunter = function activateHunter() {

			// Store the fact that hunting should be done (so it will be reactivated after a new start)
			this.setUserPref("activateHunter", "bool", true);
		

			// Start a timer (according to the user's preferences) to pull & process the HuntingTaskList periodically
			var cbhtlprocessor = this.cbhtlprocessor;
			this.TaskPullTimer = window.setInterval(function() {
				cbhtlprocessor.requestHuntingTaskList();
			}, 1000 * this.getUserPref("hunter.huntingInterval", "int"));
			
		};
		
		/**
		 * Disable Crossbear's Hunting-functionality
		 * 
		 * @param changeUserPref Flag indicating whether the Hunter should merely be disabled (e.g. because the system shuts down) or if the user additionally wants this state to be permanent.
		 */
		CBFrontend.prototype.deactivateHunter = function deactivateHunter(changeUserPref) {
			
			// If the deactivation of the Hunter should be permanent this decision needs to be stored
			if (changeUserPref) {
				this.setUserPref("activateHunter", "bool", false);
			}
			
			// Quit pulling HuntingTaskLists from the Crossbear server
			if (this.TaskPullTimer != null) {
				clearInterval(this.TaskPullTimer);
			}
			
		};
		
		/**
		 * Enable Crossbear's Guard-functionality
		 */
		CBFrontend.prototype.activateGuard = function activateGuard() {

			// Store the fact that guarding should be done (so it will be reactivated after a new start)
			this.setUserPref("activateGuard", "bool", true);

			// Tell the EventObserver to start watching for XMLHTTPRequests and to check their certificates for ALL HTTPS-connections
			this.cbeventobserver.setGuardActivity(true);
		};

		/**
		 *  Disable Crossbear's Guard-functionality
		 * 
		 * @param changeUserPref Flag indicating whether the Guard should merely be disabled (e.g. because the system shuts down) or if the user additionally wants this state to be permanent.
		 */
		CBFrontend.prototype.deactivateGuard = function deactivateGuard(changeUserPref) {

			// If the deactivation of the Guard should be permanent this decision needs to be stored
			if (changeUserPref) {
				this.setUserPref("activateGuard", "bool", false);
			}

			// Tell the EventObserver to limit the connection checking to connections to the Crossbear-Server
			this.cbeventobserver.setGuardActivity(false);

		};
		
		/**
		 * Function that handles the event that the user clicked on the Guard-Checkbox. It will invert the current activation state of the Guard.
		 */
		CBFrontend.prototype.guardCheckBoxClicked = function guardCheckBoxClicked() {
			
			// Get the current activation state of the Guard
			var oldPrefVal = this.getUserPref("activateGuard", "bool");

			// Invert the activation state
			if(oldPrefVal){
				this.deactivateGuard(true);
			} else{
				this.activateGuard();
			}

		};
		
		/**
		 * Function that handles the event that the user clicked on the Hunter-Checkbox. It will invert the current activation state of the Hunter.
		 */
		CBFrontend.prototype.hunterCheckBoxClicked = function hunterCheckBoxClicked() {
			
			// Get the current activation state of the Hunter
			var oldPrefVal = this.getUserPref("activateHunter", "bool");

			// Invert the activation state
			if(oldPrefVal){
				this.deactivateHunter(true);
			} else{
				this.activateHunter();
			}

		};
		
		/**
		 * Read the Hunter's and the Guard's current activation states and set the ticks in the cb-statusbarpanel-popup according to them.
		 */
		CBFrontend.prototype.setPopupValues = function setPopupValues() {
			
			// Get the current activation state of the Hunter ... 
			var hunterActive = this.getUserPref("activateHunter", "bool");

			// ... and set the tick in the cb-statusbarpanel-popup according to it.
			if(hunterActive){
				document.getElementById('cb-statusbarpanel-popup-hunter').setAttribute("checked", "true");
			} else if (document.getElementById('cb-statusbarpanel-popup-hunter').hasAttribute("checked")){
				document.getElementById('cb-statusbarpanel-popup-hunter').removeAttribute("checked");
			}
			
			// Get the current activation state of the Guard ...
			var guardActive = this.getUserPref("activateGuard", "bool");

			// ... and set the tick in the cb-statusbarpanel-popup according to it.
			if(guardActive){
				document.getElementById('cb-statusbarpanel-popup-guard').setAttribute("checked", "true");
			} else if (document.getElementById('cb-statusbarpanel-popup-guard').hasAttribute("checked")){
				document.getElementById('cb-statusbarpanel-popup-guard').removeAttribute("checked");
			}
			
			
		};
	}

	// Add Crossbear's certificate to the local keystore (required in order to allow http connections to it) and tell it to the CBCertificateCache. Then store it's public key in the ServerRSAKeyPair-variable for later use
	this.ServerRSAKeyPair = addCBCertToLocalStoreAndCache(this.cbcertificatecache);
	
	// Initialize the hunter (should always be initialized in order to be able to process piggy-backed HuntingTasks of CertVerifyResponses)
	this.cbhunter.init();
	
	// Initialize the guard (needs to be active to check at least the connections to the Crossbear server)
	this.cbeventobserver.initGuard();
	
	// Activate Hunter and Guard if specified by the user
	if(this.getUserPref("activateHunter", "bool"))this.activateHunter();
	if(this.getUserPref("activateGuard", "bool"))this.activateGuard();
	
}
