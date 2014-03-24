/* -*- js-indent-level: 8; -*-
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
	if (typeof (_crossbear_net_prototype_called) == 'undefined') {
		_crossbear_net_prototype_called = true;

		
		/**
		 * XMLHTTPRequests take an "onerror"-function as parameter. When the networkConnectionError-function is used as that parameter the cbFrontend.displayTechnicalFailure will be called every time a connection-error occurs. The
		 * "critical"-parameter of the cbFrontend.displayTechnicalFailure-function will be set to "true" in all cases but the case that the connection-error that occurred was a "timeout".
		 * 
		 * @param e The DOM-Event representing the error that occured
		 */
		Crossbear.CBNet.prototype.networkConnectionError = function networkConnectionError(e) {
			var errormsg = "CBNet: Error " + e.target.status + " occurred while performing a XMLHttpRequest. " +
				"URL: " + e.target.url + "\n Trace: " + e.target.trace;
			// Display a critical technical failure in all cases but the case that a timeout occurred (e.target.status == 0)
			cbFrontend.displayTechnicalFailure(errormsg, (e.target.status != 0));
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
				httpRequest.url = serverUrl;
				httpRequest.trace = new Error().stack;
				// ... and to receive binary data.
				httpRequest.responseType = "arraybuffer";

				// Set the error-handling function
				httpRequest.onerror = self.networkConnectionError;

				// Set the callback function and it's parameters
				httpRequest.onload = callBackFunction;
				httpRequest.cbCallBackParams = callBackParams;
				
				// Set the HTTP-Host-Header (required if several domains are hosted on a single IP)
				httpRequest.setRequestHeader("Host", hostName);

				// Open debug file and write post data
				// Components.utils.import("resource://gre/modules/FileUtils.jsm");
				// var file = new FileUtils.File("/home/jeeger/posted" + serverUrl.replace(/\//g, ''));
				// var stream = FileUtils.openFileOutputStream(file,FileUtils.MODE_WRONLY | FileUtils.MODE_CREATE);
				// var binarystream = Components.classes["@mozilla.org/binaryoutputstream;1"].createInstance(Components.interfaces.nsIBinaryOutputStream);
				// binarystream.setOutputStream(stream)
				// binarystream.writeByteArray(postData, postData.length)

				// Convert the Post-data into a suitable format and send it
				var bb = new Blob([postData.buffer], {"type": 'application/octet-stream'});
				httpRequest.send(bb);

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
				httpRequest.url = serverUrl;
				httpRequest.trace = new Error().stack;
				// ... and to receive binary data.
				httpRequest.responseType = "arraybuffer";

				// Set the error-handling function
				httpRequest.onerror = self.networkConnectionError;

				// Set the callback function and it's parameters
				httpRequest.onload = callBackFunction;
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
				dnsService.asyncResolve(serverHostName, dnsService.RESOLVE_DISABLE_IPV6, callbackObject, target);

			} catch (e) {
				cbFrontend.displayTechnicalFailure("CBNet:requestServerDNS: could not retrieve DNS for " + serverHostName + "!", true);
			}
		};

	}

};
