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
 * This class bundles all functionality that is related to
 * - Displaying information/warnings to the user
 * - Getting and setting the user's preferences 
 * - (de-)activation of the Hunter/Protector
 * - System initialization and shutdown
 * 
 * @param cbServerName The Hostname of the Crossbear server (e.g. crossbear.net.in.tum.de)
 * 
 * @author Thomas Riedmaier
 */
Crossbear.CBFrontend = function (cbServerName) {

	// The Hostname of the Crossbear server
	this.cbServerName = cbServerName;
	
	// The difference between the local time and the Crossbear server time: cbServerTimeDiff = cbServerTime-localTime
	this.cbServerTimeDiff = 'undefined';
	
	// Remembers if a shutdown was requested (required in order not to do deinitialization twice). If this is set to true the loop inside the "UnknownCertDlg" will quit
	this.shutdownWasRequested = false;

	// Initialize the rest of the Crossbear system (if possible)
	this.cbdatabase = new Crossbear.CBDatabase(this);
	this.cbnet = new Crossbear.CBNet(this);
	this.cbhunter = new Crossbear.CBHunter(this);
	this.cbprotector = new Crossbear.CBProtector(this);
	this.cbhtlprocessor = new Crossbear.CBHTLProcessor(this);
	this.cbtrustdecisioncache = new Crossbear.CBTrustDecisionCache(this);
	this.cbeventobserver = new Crossbear.CBEventObserver(this);

	// Some elements require functions from CBFrontend and will therefore initialized below.
	this.TaskPullTimer = null;
	this.ServerRSAKeyPair = null;
	
	// Open Firefox components related to logging into the Console and Accessing User-Preferences
	var consoleService = Components.classes["@mozilla.org/consoleservice;1"].getService(Components.interfaces.nsIConsoleService);
	var prefs = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefService).getBranch("extensions.crossbear.");
	var defPrefs = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefService).getDefaultBranch("extensions.crossbear.");
	
	// Load the AddonManager so it can be checked whether Convergence is installed and active
	Components.utils.import("resource://gre/modules/AddonManager.jsm");
	
	// "this" does not always point to THIS object (especially in callback functions). Therefore I use the "self" variable to hold a handle on THIS object
	var self = this;
	
	// Initialize the member function references for the class prototype (like this it's only done once and not every time a instance of this object is created)
	if (typeof (_crossbear_frontend_prototype_called) == 'undefined') {
		_crossbear_frontend_prototype_called = true;

		/**
		 * Display an exception caused by a technical failure
		 * 
		 * @param what The message that should be displayed
		 * @param critical If True Crossbear will be shut down after the displaying the exception
		 */
		Crossbear.CBFrontend.prototype.displayTechnicalFailure = function displayTechnicalFailure(what, critical) {
			
			// Display the message of the failure in the "Error"-tab of the Error Console
			Components.utils.reportError(what);
			
			// If the exception was a critical one: Shutdown the system ...
			if (critical) {
				this.shutdown(true);
				
				// ... display a Message-Box so the user is aware that something went wrong
				var crashText = "Crossbear just crashed :(\n This might be caused by a change in the protocol. Please make sure you use the latest version of Crossbear!";
				alert(crashText);
				
				// .. and finally crash ;)
				throw crashText;
			}

		};

		/**
		 * Get an estimation of the current local time of the Crossbear server
		 * @returns A timestamp that is an estimation of the current local time of the Crossbear server
		 */
		Crossbear.CBFrontend.prototype.getServerTime = function getServerTime() {
			
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
		Crossbear.CBFrontend.prototype.calcAndStoreCbServerTimeDiff = function calcAndStoreCbServerTimeDiff(currentServerTime) {
			this.cbServerTimeDiff = currentServerTime-Math.round(new Date().getTime() / 1000);
		};
		
		/**
		 * Display an information to the user. This is currently done by writing into the "Information"-tab of the Error Console
		 * 
		 * @param what The message to display
		 */
		Crossbear.CBFrontend.prototype.displayInformation = function displayInformation(what) {
			// Alternative for the line below: console.log
			consoleService.logStringMessage("CB:"+new Date().toUTCString()+":"+what);
		};

		/**
		 * Warn the user that system might currently be under attack. This is currently done by displaying a WarnUserDlg
		 * 
		 * @param warningXML The message explaining the threat that the user is supposingly facing (MUST be a XML object)
		 * @param timeoutSec A Timeout parameter specifying how long the warning is minimally displayed
		 */
		Crossbear.CBFrontend.prototype.warnUserAboutBeingUnderAttack = function warnUserAboutBeingUnderAttack(warningXML, timeoutSec) {

			// Build an object containing the parameters for the WarnUserDlg
			var params = {
				inn : {
					warningXML : warningXML,
					timeoutSec : timeoutSec
				},
				out : {}
			};

			// Open the Dialog
			window.openDialog("chrome://crossbear/content/gui/WarnUserDlg.xul", "Crossbear - Warning you about a security Threat", "chrome,centerscreen,dependent=YES,dialog=YES,modal=YES,close=no,resizable=no", params);
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
		Crossbear.CBFrontend.prototype.getDefaultPref = function getDefaultPref(name, type) {
			try {
				// Read the preference according to its type and return it
				if (Crossbear.startsWith(type,"bool")) {
					return defPrefs.getBoolPref(name);
				} else if (Crossbear.startsWith(type,"int")) {
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
		Crossbear.CBFrontend.prototype.getUserPref = function getUserPref(name, type) {
			try {
				// Read the preference according to its type and return it
				if (Crossbear.startsWith(type,"bool")) {
					return prefs.getBoolPref(name);
				} else if (Crossbear.startsWith(type,"int")) {
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
		Crossbear.CBFrontend.prototype.setUserPref = function setUserPref(name, type, value) {
			try {
				// Set the preference according to its type
				if (Crossbear.startsWith(type,"bool")) {
					prefs.setBoolPref(name, value);
				} else if (Crossbear.startsWith(type,"int")) {
					prefs.setIntPref(name, value);
				} else {
					prefs.setCharPref(name, value);
				}
			} catch (e) {
				this.displayTechnicalFailure("CBFrontend:setUserPref: An error occured while setting "+name+"("+type+") to "+value+": " + e, true);
			}
		};
		
		/**
		 * Startup Crossbear
		 */
		Crossbear.CBFrontend.prototype.startup = function startup() {
			
			// Add Crossbear's certificate to the local keystore (required in order to allow http connections to it) and tell it to the CBTrustDecisionCache. Then store it's public key in the ServerRSAKeyPair-variable for later use
			this.ServerRSAKeyPair = Crossbear.loadCBCertAndAddToCache(this.cbtrustdecisioncache);
			
			// Initialize the hunter (should always be initialized in order to be able to process piggy-backed HuntingTasks of CertVerifyResponses)
			this.cbhunter.init();
			
			
			// Activate Hunter and Protector if specified by the user
			if(this.getUserPref("activateHunter", "bool"))this.activateHunter();
			if(this.getUserPref("activateProtector", "bool"))this.activateProtector();
			
			// Check if Convergence is installed. If it is: deactivate Crossbear!  
		    AddonManager.getAddonByID("convergence@extension.thoughtcrime.org", function(addon) {  
		      if(addon != null && addon.isActive){
		          var convergenceWarningXML = document.implementation.createDocument(null, "p", null);
			  var convergenceWarning = convergenceWarningXML.createTextNode("You are running Convergence. Since Crossbear cannot operate while Convergence is present, Crossbear was deactivated. Please uninstall either of the two add-ons. Note that Crossbear queries Convergence, so there is no need for the latter.");
                          convergenceWarningXML.appendChild(convergenceWarning);
		    	  self.warnUserAboutBeingUnderAttack(convergenceWarningXML, 0);
		    	  self.shutdown(true);
		      } 
		    });  
			
		};

		/**
		 * Shutdown Crossbear
		 * 
		 * @param systemCrashed Flag indicating if the system performs a normal shutdown or if it crashed.
		 */
		Crossbear.CBFrontend.prototype.shutdown = function shutdown(systemCrashed) {
			
			// Only shut down if the system is active
			if(!this.shutdownWasRequested){
				
				// Mark the system as inactive (so the shutdown is not performed twice)
				this.shutdownWasRequested = true;
				
				// Deactivate the Protector
				this.deactivateProtector(systemCrashed);
				
				
				// Deactivate the Hunter
				this.deactivateHunter(systemCrashed);
				
				// Terminate any running HuntingTasks
				this.cbhunter.terminate();

			}

		};
		
		/**
		 * Enable Crossbear's Hunting-functionality
		 */
		Crossbear.CBFrontend.prototype.activateHunter = function activateHunter() {

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
		Crossbear.CBFrontend.prototype.deactivateHunter = function deactivateHunter(changeUserPref) {
			
			// If the deactivation of the Hunter should be permanent this decision needs to be stored
			if (changeUserPref) {
				this.setUserPref("activateHunter", "bool", false);
			}
			
			// Quit pulling HuntingTaskLists from the Crossbear server
			if (this.TaskPullTimer != null) {
				window.clearInterval(this.TaskPullTimer);
			}
			
		};
		
		/**
		 * Enable Crossbear's Protector-functionality
		 */
		Crossbear.CBFrontend.prototype.activateProtector = function activateProtector() {

			// Store the fact that protectoring should be done (so it will be reactivated after a new start)
			this.setUserPref("activateProtector", "bool", true);

			// Tell the EventObserver to start watching for XMLHTTPRequests and to check their certificates for ALL HTTPS-connections
			this.cbeventobserver.setProtectorActivity(true);
		};

		/**
		 *  Disable Crossbear's Protector-functionality
		 * 
		 * @param changeUserPref Flag indicating whether the Protector should merely be disabled (e.g. because the system shuts down) or if the user additionally wants this state to be permanent.
		 */
		Crossbear.CBFrontend.prototype.deactivateProtector = function deactivateProtector(changeUserPref) {

			// If the deactivation of the Protector should be permanent this decision needs to be stored
			if (changeUserPref) {
				this.setUserPref("activateProtector", "bool", false);
			}

			// Tell the EventObserver to limit the connection checking to connections to the Crossbear-Server
			this.cbeventobserver.setProtectorActivity(false);

		};
		
		/**
		 * Function that handles the event that the user clicked on the Protector-Checkbox. It will invert the current activation state of the Protector.
		 */
		Crossbear.CBFrontend.prototype.protectorCheckBoxClicked = function protectorCheckBoxClicked() {
			
			// Get the current activation state of the Protector
			var oldPrefVal = this.getUserPref("activateProtector", "bool");

			// Invert the activation state
			if(oldPrefVal){
				this.deactivateProtector(true);
			} else{
				this.activateProtector();
			}

		};
		
		/**
		 * Function that handles the event that the user clicked on the Hunter-Checkbox. It will invert the current activation state of the Hunter.
		 */
		Crossbear.CBFrontend.prototype.hunterCheckBoxClicked = function hunterCheckBoxClicked() {
			
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
		 * Read the Hunter's and the Protector's current activation states and set the ticks in the crossbear-statusbarpanel-popup according to them.
		 */
		Crossbear.CBFrontend.prototype.setPopupValues = function setPopupValues() {
			
			// Get the current activation state of the Hunter ... 
			var hunterActive = this.getUserPref("activateHunter", "bool");

			// ... and set the tick in the crossbear-statusbarpanel-popup according to it.
			if(hunterActive){
				document.getElementById('crossbear-statusbarpanel-popup-hunter').setAttribute("checked", "true");
			} else if (document.getElementById('crossbear-statusbarpanel-popup-hunter').hasAttribute("checked")){
				document.getElementById('crossbear-statusbarpanel-popup-hunter').removeAttribute("checked");
			}
			
			// Get the current activation state of the Protector ...
			var protectorActive = this.getUserPref("activateProtector", "bool");

			// ... and set the tick in the crossbear-statusbarpanel-popup according to it.
			if(protectorActive){
				document.getElementById('crossbear-statusbarpanel-popup-protector').setAttribute("checked", "true");
			} else if (document.getElementById('crossbear-statusbarpanel-popup-protector').hasAttribute("checked")){
				document.getElementById('crossbear-statusbarpanel-popup-protector').removeAttribute("checked");
			}
			
			
		};
	}
	
	// Startup the Crossbear system
	this.startup();
	
};
