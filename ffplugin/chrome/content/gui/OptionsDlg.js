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
 * This dialog displays the user's preferences and provides a GUI to change them
 */

/**
 * Initialization function (called once when the dialog is about to display)
 */
function onLoad() {
	
	// Load the protector.trustAutomatically-setting and set its GUI equivalent
	if(window.arguments[0].inn.cbFrontend.getUserPref("protector.trustAutomatically", "bool")){
		document.getElementById("crossbear-opt-trust-automatically").selectedIndex = 0;
	}
	else {
		document.getElementById("crossbear-opt-trust-automatically").selectedIndex = 1;
	}
	
	// Load the protector.ratingToTrustAutomatically-setting and set its GUI equivalent
	document.getElementById("crossbear-opt-trust-req-rating").value = window.arguments[0].inn.cbFrontend.getUserPref("protector.ratingToTrustAutomatically", "int");

	// Load the protector.tdcValidity-setting and set its GUI equivalent
	document.getElementById("crossbear-opt-tdc-validity").value = window.arguments[0].inn.cbFrontend.getUserPref("protector.tdcValidity", "int");
	
	// Load the protector.showRedirectWarning-setting and set its GUI equivalent
	if(window.arguments[0].inn.cbFrontend.getUserPref("protector.showRedirectWarning", "bool")){
		document.getElementById("crossbear-opt-redirect-warning").selectedIndex = 0;
	}
	else {
		document.getElementById("crossbear-opt-redirect-warning").selectedIndex = 1;
	}
	
	// Load the hunter.huntingInterval-setting and set its GUI equivalent
	document.getElementById("crossbear-opt-hunting-interval").value = window.arguments[0].inn.cbFrontend.getUserPref("hunter.huntingInterval", "int");

	// Load the hunter.taskReexecutionInterval-setting and set its GUI equivalent
	document.getElementById("crossbear-opt-hunting-reexecution-interval").value = window.arguments[0].inn.cbFrontend.getUserPref("hunter.taskReexecutionInterval", "int");
	
	// Load the hunter.tracerouteMaxHops-setting and set its GUI equivalent
	document.getElementById("crossbear-opt-traceroute-max-hops").value = window.arguments[0].inn.cbFrontend.getUserPref("hunter.tracerouteMaxHops", "int");

	// Load the hunter.tracerouteSamplesPerHop-setting and set its GUI equivalent
	document.getElementById("crossbear-opt-traceroute-samples-per-hop").value = window.arguments[0].inn.cbFrontend.getUserPref("hunter.tracerouteSamplesPerHop", "int");

	// Load the hunter.publicIPcacheValidity-setting and set its GUI equivalent
	document.getElementById("crossbear-opt-trust-pub-ip-cache-validity").value = window.arguments[0].inn.cbFrontend.getUserPref("hunter.publicIPcacheValidity", "int");

	// Load the hunter.serverIPcacheValidity-setting and set its GUI equivalent
	document.getElementById("crossbear-opt-trust-serv-ip-cache-validity").value = window.arguments[0].inn.cbFrontend.getUserPref("hunter.serverIPcacheValidity", "int");
}

/**
 * Load the default values of for all preferences
 */
function loadDefaults() {
	
	// Load the default value of the protector.trustAutomatically-setting and set its GUI equivalent
	if(window.arguments[0].inn.cbFrontend.getDefaultPref("protector.trustAutomatically", "bool")){
		document.getElementById("crossbear-opt-trust-automatically").selectedIndex = 0;
	}
	else {
		document.getElementById("crossbear-opt-trust-automatically").selectedIndex = 1;
	}
	
	// Load the default value of the protector.ratingToTrustAutomatically-setting and set its GUI equivalent
	document.getElementById("crossbear-opt-trust-req-rating").value = window.arguments[0].inn.cbFrontend.getDefaultPref("protector.ratingToTrustAutomatically", "int");

	// Load the default value of the protector.tdcValidity-setting and set its GUI equivalent
	document.getElementById("crossbear-opt-tdc-validity").value =  window.arguments[0].inn.cbFrontend.getDefaultPref("protector.tdcValidity", "int");

	// Load the default value of the protector.showRedirectWarning-setting and set its GUI equivalent
	if(window.arguments[0].inn.cbFrontend.getDefaultPref("protector.showRedirectWarning", "bool")){
		document.getElementById("crossbear-opt-redirect-warning").selectedIndex = 0;
	}
	else {
		document.getElementById("crossbear-opt-redirect-warning").selectedIndex = 1;
	}
	
	// Load the default value of the hunter.huntingInterval-setting and set its GUI equivalent
	document.getElementById("crossbear-opt-hunting-interval").value = window.arguments[0].inn.cbFrontend.getDefaultPref("hunter.huntingInterval", "int");

	// Load the default value of the hunter.taskReexecutionInterval-setting and set its GUI equivalent
	document.getElementById("crossbear-opt-hunting-reexecution-interval").value = window.arguments[0].inn.cbFrontend.getDefaultPref("hunter.taskReexecutionInterval", "int");
	
	// Load the default value of the hunter.tracerouteMaxHops-setting and set its GUI equivalent
	document.getElementById("crossbear-opt-traceroute-max-hops").value = window.arguments[0].inn.cbFrontend.getDefaultPref("hunter.tracerouteMaxHops", "int");

	// Load the default value of the hunter.tracerouteSamplesPerHop-setting and set its GUI equivalent
	document.getElementById("crossbear-opt-traceroute-samples-per-hop").value = window.arguments[0].inn.cbFrontend.getDefaultPref("hunter.tracerouteSamplesPerHop", "int");

	// Load the default value of the hunter.publicIPcacheValidity-setting and set its GUI equivalent
	document.getElementById("crossbear-opt-trust-pub-ip-cache-validity").value = window.arguments[0].inn.cbFrontend.getDefaultPref("hunter.publicIPcacheValidity", "int");

	// Load the default value of the hunter.serverIPcacheValidity-setting and set its GUI equivalent
	document.getElementById("crossbear-opt-trust-serv-ip-cache-validity").value = window.arguments[0].inn.cbFrontend.getDefaultPref("hunter.serverIPcacheValidity", "int");
}

/**
 * Read the preferences the user entered in the GUI and store them
 * 
 * @returns true (So the dialog will be closed)
 */
function accept() {
	
	// Read the protector.trustAutomatically from its GUI equivalent and store it
	window.arguments[0].inn.cbFrontend.setUserPref("protector.trustAutomatically", "bool",document.getElementById("crossbear-opt-trust-automatically-yes").selected);

	// Read the protector.ratingToTrustAutomatically from its GUI equivalent and store it
	window.arguments[0].inn.cbFrontend.setUserPref("protector.ratingToTrustAutomatically", "int", document.getElementById("crossbear-opt-trust-req-rating").value);

	// Read the protector.tdcValidity from its GUI equivalent and store it
	window.arguments[0].inn.cbFrontend.setUserPref("protector.tdcValidity", "int", document.getElementById("crossbear-opt-tdc-validity").value);

	// Read the protector.showRedirectWarning from its GUI equivalent and store it
	window.arguments[0].inn.cbFrontend.setUserPref("protector.showRedirectWarning", "bool",document.getElementById("crossbear-opt-redirect-warning-yes").selected);
	
	// Read the hunter.huntingInterval from its GUI equivalent and store it
	window.arguments[0].inn.cbFrontend.setUserPref("hunter.huntingInterval", "int", document.getElementById("crossbear-opt-hunting-interval").value);

	// Read the hunter.taskReexecutionInterval from its GUI equivalent and store it
	window.arguments[0].inn.cbFrontend.setUserPref("hunter.taskReexecutionInterval", "int", document.getElementById("crossbear-opt-hunting-reexecution-interval").value);
	
	// Read the hunter.tracerouteMaxHops from its GUI equivalent and store it
	window.arguments[0].inn.cbFrontend.setUserPref("hunter.tracerouteMaxHops", "int", document.getElementById("crossbear-opt-traceroute-max-hops").value);

	// Read the hunter.tracerouteSamplesPerHop from its GUI equivalent and store it
	window.arguments[0].inn.cbFrontend.setUserPref("hunter.tracerouteSamplesPerHop", "int", document.getElementById("crossbear-opt-traceroute-samples-per-hop").value);

	// Read the hunter.publicIPcacheValidity from its GUI equivalent and store it
	window.arguments[0].inn.cbFrontend.setUserPref("hunter.publicIPcacheValidity", "int", document.getElementById("crossbear-opt-trust-pub-ip-cache-validity").value);

	// Read the hunter.serverIPcacheValidity from its GUI equivalent and store it
	window.arguments[0].inn.cbFrontend.setUserPref("hunter.serverIPcacheValidity", "int", document.getElementById("crossbear-opt-trust-serv-ip-cache-validity").value);
	
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