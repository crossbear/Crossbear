// -*- js-indent-level: 8; -*-
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
 * This dialog displays the user's preferences and provides a GUI to change them
 */

var prefs;
var preferences = Components.classes["@mozilla.org/preferences-service;1"]
	.getService(Components.interfaces.nsIPrefService);

prefs = {};
prefs.getUserPref = function (name, type) {
	var branch = preferences.getBranch("extensions.crossbear.");
	// Read the preference according to its type and return it
	if (Crossbear.startsWith(type,"bool")) {
		return branch.getBoolPref(name);
	} else if (Crossbear.startsWith(type,"int")) {
		return branch.getIntPref(name);
	} else {
		return branch.getCharPref(name);
	}
};

prefs.setUserPref = function (name, type, value) {
	var branch = preferences.getBranch("extensions.crossbear.");
	// Set the preference according to its type
	if (Crossbear.startsWith(type,"bool")) {
		branch.setBoolPref(name, value);
	} else if (Crossbear.startsWith(type,"int")) {
		branch.setIntPref(name, value);
	} else {
		branch.setCharPref(name, value);
	}
};

prefs.getDefaultPref = function	(name, type) {
	var branch = preferences.getDefaultBranch("extensions.crossbear.");
	// Read the preference according to its type and return it
	if (Crossbear.startsWith(type,"bool")) {
		return branch.getBoolPref(name);
	} else if (Crossbear.startsWith(type,"int")) {
		return branch.getIntPref(name);
	} else {
		return branch.getCharPref(name);
	}
};

/**
 * Initialization function (called once when the dialog is about to display)
 */
function onLoad() {

	// Load the protector.trustAutomatically-setting and set its GUI equivalent
	if(prefs.getUserPref("protector.trustAutomatically", "bool")){
		document.getElementById("crossbear-opt-trust-automatically").selectedIndex = 0;
	}
	else {
		document.getElementById("crossbear-opt-trust-automatically").selectedIndex = 1;
	}

	// Load the protector.ratingToTrustAutomatically-setting and set its GUI equivalent
	document.getElementById("crossbear-opt-trust-req-rating").value = prefs.getUserPref("protector.ratingToTrustAutomatically", "int");

	// Load the protector.tdcValidity-setting and set its GUI equivalent
	document.getElementById("crossbear-opt-tdc-validity").value = prefs.getUserPref("protector.tdcValidity", "int");

	// Load the protector.showRedirectWarning-setting and set its GUI equivalent
	if(prefs.getUserPref("protector.showRedirectWarning", "bool")){
		document.getElementById("crossbear-opt-redirect-warning").selectedIndex = 0;
	}
	else {
		document.getElementById("crossbear-opt-redirect-warning").selectedIndex = 1;
	}

	// Load the hunter.huntingInterval-setting and set its GUI equivalent
	document.getElementById("crossbear-opt-hunting-interval").value = prefs.getUserPref("hunter.huntingInterval", "int");

	// Load the hunter.taskReexecutionInterval-setting and set its GUI equivalent
	document.getElementById("crossbear-opt-hunting-reexecution-interval").value = prefs.getUserPref("hunter.taskReexecutionInterval", "int");

	// Load the hunter.tracerouteMaxHops-setting and set its GUI equivalent
	document.getElementById("crossbear-opt-traceroute-max-hops").value = prefs.getUserPref("hunter.tracerouteMaxHops", "int");

	// Load the hunter.tracerouteSamplesPerHop-setting and set its GUI equivalent
	document.getElementById("crossbear-opt-traceroute-samples-per-hop").value = prefs.getUserPref("hunter.tracerouteSamplesPerHop", "int");

	// Load the hunter.publicIPcacheValidity-setting and set its GUI equivalent
	document.getElementById("crossbear-opt-trust-pub-ip-cache-validity").value = prefs.getUserPref("hunter.publicIPcacheValidity", "int");

	// Load the hunter.serverIPcacheValidity-setting and set its GUI equivalent
	document.getElementById("crossbear-opt-trust-serv-ip-cache-validity").value = prefs.getUserPref("hunter.serverIPcacheValidity", "int");
}

/**
 * Load the default values of for all preferences
 */
function loadDefaults() {
	
	// Load the default value of the protector.trustAutomatically-setting and set its GUI equivalent
	if(prefs.getDefaultPref("protector.trustAutomatically", "bool")){
		document.getElementById("crossbear-opt-trust-automatically").selectedIndex = 0;
	}
	else {
		document.getElementById("crossbear-opt-trust-automatically").selectedIndex = 1;
	}
	
	// Load the default value of the protector.ratingToTrustAutomatically-setting and set its GUI equivalent
	document.getElementById("crossbear-opt-trust-req-rating").value = prefs.getDefaultPref("protector.ratingToTrustAutomatically", "int");

	// Load the default value of the protector.tdcValidity-setting and set its GUI equivalent
	document.getElementById("crossbear-opt-tdc-validity").value =  prefs.getDefaultPref("protector.tdcValidity", "int");

	// Load the default value of the protector.showRedirectWarning-setting and set its GUI equivalent
	if(prefs.getDefaultPref("protector.showRedirectWarning", "bool")){
		document.getElementById("crossbear-opt-redirect-warning").selectedIndex = 0;
	}
	else {
		document.getElementById("crossbear-opt-redirect-warning").selectedIndex = 1;
	}
	
	// Load the default value of the hunter.huntingInterval-setting and set its GUI equivalent
	document.getElementById("crossbear-opt-hunting-interval").value = prefs.getDefaultPref("hunter.huntingInterval", "int");

	// Load the default value of the hunter.taskReexecutionInterval-setting and set its GUI equivalent
	document.getElementById("crossbear-opt-hunting-reexecution-interval").value = prefs.getDefaultPref("hunter.taskReexecutionInterval", "int");
	
	// Load the default value of the hunter.tracerouteMaxHops-setting and set its GUI equivalent
	document.getElementById("crossbear-opt-traceroute-max-hops").value = prefs.getDefaultPref("hunter.tracerouteMaxHops", "int");

	// Load the default value of the hunter.tracerouteSamplesPerHop-setting and set its GUI equivalent
	document.getElementById("crossbear-opt-traceroute-samples-per-hop").value = prefs.getDefaultPref("hunter.tracerouteSamplesPerHop", "int");

	// Load the default value of the hunter.publicIPcacheValidity-setting and set its GUI equivalent
	document.getElementById("crossbear-opt-trust-pub-ip-cache-validity").value = prefs.getDefaultPref("hunter.publicIPcacheValidity", "int");

	// Load the default value of the hunter.serverIPcacheValidity-setting and set its GUI equivalent
	document.getElementById("crossbear-opt-trust-serv-ip-cache-validity").value = prefs.getDefaultPref("hunter.serverIPcacheValidity", "int");
}

/**
 * Read the preferences the user entered in the GUI and store them
 * 
 * @returns true (So the dialog will be closed)
 */
function accept() {
	
	// Read the protector.trustAutomatically from its GUI equivalent and store it
	prefs.setUserPref("protector.trustAutomatically", "bool",document.getElementById("crossbear-opt-trust-automatically-yes").selected);

	// Read the protector.ratingToTrustAutomatically from its GUI equivalent and store it
	prefs.setUserPref("protector.ratingToTrustAutomatically", "int", document.getElementById("crossbear-opt-trust-req-rating").value);

	// Read the protector.tdcValidity from its GUI equivalent and store it
	prefs.setUserPref("protector.tdcValidity", "int", document.getElementById("crossbear-opt-tdc-validity").value);

	// Read the protector.showRedirectWarning from its GUI equivalent and store it
	prefs.setUserPref("protector.showRedirectWarning", "bool",document.getElementById("crossbear-opt-redirect-warning-yes").selected);
	
	// Read the hunter.huntingInterval from its GUI equivalent and store it
	prefs.setUserPref("hunter.huntingInterval", "int", document.getElementById("crossbear-opt-hunting-interval").value);

	// Read the hunter.taskReexecutionInterval from its GUI equivalent and store it
	prefs.setUserPref("hunter.taskReexecutionInterval", "int", document.getElementById("crossbear-opt-hunting-reexecution-interval").value);
	
	// Read the hunter.tracerouteMaxHops from its GUI equivalent and store it
	prefs.setUserPref("hunter.tracerouteMaxHops", "int", document.getElementById("crossbear-opt-traceroute-max-hops").value);

	// Read the hunter.tracerouteSamplesPerHop from its GUI equivalent and store it
	prefs.setUserPref("hunter.tracerouteSamplesPerHop", "int", document.getElementById("crossbear-opt-traceroute-samples-per-hop").value);

	// Read the hunter.publicIPcacheValidity from its GUI equivalent and store it
	prefs.setUserPref("hunter.publicIPcacheValidity", "int", document.getElementById("crossbear-opt-trust-pub-ip-cache-validity").value);

	// Read the hunter.serverIPcacheValidity from its GUI equivalent and store it
	prefs.setUserPref("hunter.serverIPcacheValidity", "int", document.getElementById("crossbear-opt-trust-serv-ip-cache-validity").value);
	
	// Return true (So the dialog will be closed)
	return true;
}

/**
 * Close the dialog without making any changes to the user's preferences
 * 
 * @returns true (So the dialog will be closed)
 */
function cancel() {
	return true;
}
