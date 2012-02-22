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
 * The CBNet-class bundles all functionality that is connected with networking apart from the Traceroute-functionality (moved to CBTracer) and the Certificate-Chain-Fetching-functionality (moved to CBCertifiateChainFetcher)
 * 
 * @param cbFrontend The cbFrontend-class that will be used to display information/errors
 * 
 * @author Thomas Riedmaier
 */
Crossbear.CBNet = function (cbFrontend) {
	this.cbFrontend = cbFrontend;

	// "this" does not always point to THIS object (especially in callback functions). Therefore I use the "self" variable to hold a handle on THIS object
	var self = this;

	// Initialize the member function references for the class prototype (like this it's only done once and not every time a instance of this object is created)
	if (typeof (_cbnet_prototype_called) == 'undefined') {
		_cbnet_prototype_called = true;

		
		/**
		 * XMLHTTPRequests take an "onerror"-function as parameter. When the networkConnectionError-function is used as that parameter the cbFrontend.displayTechnicalFailure will be called every time a connection-error occurs. The
		 * "critical"-parameter of the cbFrontend.displayTechnicalFailure-function will be set to "true" in all cases but the case that the connection-error that occurred was a "timeout".
		 * 
		 * @param e The DOM-Event representing the error that occured
		 */
		Crossbear.CBNet.prototype.networkConnectionError = function networkConnectionError(e) {
			// Display a critical technical failure in all cases but the case that a timeout occurred (e.target.status == 0)
			cbFrontend.displayTechnicalFailure("CBNet: Error " + e.target.status + " occurred while performing a XMLHttpRequest.", (e.target.status != 0));
		};

	
		/**
		 * Post binary data to a URL and retrieve the server's reply as binary data.
		 *  
		 * The code was created by the use of https://developer.mozilla.org/En/XMLHttpRequest/Using_XMLHttpRequest#Receiving_binary_data_using_JavaScript_typed_arrays
		 *  
		 * @param serverUrl The URL to post the data to (e.g. http://www.somedomain.org/submitform.php)
		 * @param hostName The Hostname part of the URL (e.g. www.somedomain.org) -> required if several domains are hosted on a single IP
		 * @param postData The data to post (has to be a Uint8Array -> call jsArrayToUint8Array to convert it)
		 * @param callBackFunction The function that will be called to handle the server's reply (must be set)
		 * @param callBackParams Data that should be available to the callBackFunction can be passed here. It will be accessible via "this.cbCallBackParams". If you don't need them just pass "null"
		 */
		Crossbear.CBNet.prototype.postBinaryRetrieveBinaryFromUrl = function postDataRetrieveBinaryFromUrl(serverUrl, hostName, postData, callBackFunction, callBackParams) {

			// Posting no data is not possible. Call retrieveBinaryFromUrl instead
			if ((postData == null) || (postData == "")) {
				cbFrontend.displayTechnicalFailure("CBNet:postBinaryRetrieveBinaryFromUrl was called without post data!", true);
				return;
			}

			try {
				// Create a new XMLHTTPRequest
				var httpRequest = Components.classes["@mozilla.org/xmlextras/xmlhttprequest;1"].createInstance();
				
				// Disable alert popups on SSL error
				httpRequest.mozBackgroundRequest = true;

				// Set the Request to Post data ...
				httpRequest.open("POST", serverUrl, true);
				
				// ... and to receive binary data.
				httpRequest.responseType = "arraybuffer";

				// Set the error-handling function
				httpRequest.onerror = self.networkConnectionError;

				// Set the callback function and it's parameters
				httpRequest.onreadystatechange = callBackFunction;
				httpRequest.cbCallBackParams = callBackParams;
				
				// Set the HTTP-Host-Header (required if several domains are hosted on a single IP)
				httpRequest.setRequestHeader("Host", hostName);

				// Convert the Post-data into a suitable format and send it
				var bb = new MozBlobBuilder();
				bb.append(postData.buffer);
				httpRequest.send(bb.getBlob('application/octet-stream'));

			} catch (e) {
				cbFrontend.displayTechnicalFailure("CBNet:postBinaryRetrieveBinaryFromUrl: could not connect to the specified server: " + e, true);
			}
		};

		/**
		 * Retrieve binary data from a server.
		 *  
		 * The code was created by the use of https://developer.mozilla.org/En/XMLHttpRequest/Using_XMLHttpRequest#Receiving_binary_data_using_JavaScript_typed_arrays
		 * 
		 * @param serverUrl The URL to post the data to (e.g. http://www.somedomain.org/submitform.php)
		 * @param hostName The Hostname part of the URL (e.g. www.somedomain.org) -> required if several domains are hosted on a single IP
		 * @param callBackFunction The function that will be called to handle the server's reply (must be set)
		 * @param callBackParams callBackParams Data that should be available to the callBackFunction can be passed here. It will be accessible via "this.cbCallBackParams". If you don't need them just pass "null"
		 */
		Crossbear.CBNet.prototype.retrieveBinaryFromUrl = function retrieveBinaryFromUrl(serverUrl, hostName, callBackFunction, callBackParams) {

			try {
				// Create a new XMLHTTPRequest
				var httpRequest = Components.classes["@mozilla.org/xmlextras/xmlhttprequest;1"].createInstance();

				// Disable alert popups on SSL error
				httpRequest.mozBackgroundRequest = true;

				// Set the Request to Get data ...
				httpRequest.open("GET", serverUrl, true);
				
				// ... and to receive binary data.
				httpRequest.responseType = "arraybuffer";

				// Set the error-handling function
				httpRequest.onerror = self.networkConnectionError;

				// Set the callback function and it's parameters
				httpRequest.onreadystatechange = callBackFunction;
				httpRequest.cbCallBackParams = callBackParams;
				
				// Set the HTTP-Host-Header (required if several domains are hosted on a single IP)
				httpRequest.setRequestHeader("Host", hostName);
				
				// Finally: Send the request
				httpRequest.send(null);
			} catch (e) {
				cbFrontend.displayTechnicalFailure("CBNet:RetrieveBinaryFromUrl: could not connect to the specified server: " + e, true);
			}
		};
		
		/**
		 * Perform a DNS-request on a server's Hostname.
		 * 
		 * @param serverHostName The Hostname to lookup (e.g. www.somedomain.org)
		 * @param callbackObject An Object implementing the nsIDNSListener-Interface. Its onLookupComplete-function will be called when the DNS-lookup is completed 
		 */
		Crossbear.CBNet.prototype.requestServerDNS = function requestServerDNS(serverHostName, callbackObject) {

			try {
				// Get a handle for the DNS-service
				var dnsService = Components.classes["@mozilla.org/network/dns-service;1"].createInstance(Components.interfaces.nsIDNSService);
				
				// Get a handle for the current Thread
				var target = Components.classes["@mozilla.org/thread-manager;1"].getService().currentThread;

				// Perform a DNS-request on serverHostName with callbackObject as callback
				dnsService.asyncResolve(serverHostName, 0, callbackObject, target);

			} catch (e) {
				cbFrontend.displayTechnicalFailure("CBNet:requestServerDNS: could not retrieve DNS for " + serverHostName + "!", true);
			}
		};

	}

};
