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
 * The CBProtector-class is the local system's interface to the server's certificate verification functionality. When asked to perform a certificate verification this class will forward the request to the server and parse its answer. If the user chose to
 * use the automatic-trust-setting and the server responds with a high rating then the only thing that is done is a Cache-update. In all other cases a UnknownCertDlg will be displayed.
 * 
 * If the same request is uttered more than once, only a single request will be sent to the Crossbear server.
 * 
 * Please Note: This class maintains an internal list of CertVerificationRequests which will only work as long as this class is accessed by a single thread only. Therefore it is assumed that there is only one GUI-Thread,
 * which is true to our best knowledge.
 * 
 * @param cbFrontend The cbFrontend-class that will be used to display information/errors to the user and to read the user preferences and settings.
 * 
 * @author Thomas Riedmaier
 * @author Ralph Holz
 */
Crossbear.CBProtector = function (cbFrontend) {
	this.cbFrontend = cbFrontend;

	// The list of all CertificateVerificationRequests that are to be done. This list does not include any duplicates for performance reasons (see class description).
	this.requestsPending = [];

	// "this" does not always point to THIS object (especially in callback functions). Therefore I use the "self" variable to hold a handle on THIS object
	var self = this;

	// Open Firefox components required to find out whether a user uses a proxy for a certain connection
	var pps = Components.classes["@mozilla.org/network/protocol-proxy-service;1"].getService(Components.interfaces.nsIProtocolProxyService);
	var ioService = Components.classes["@mozilla.org/network/io-service;1"].getService(Components.interfaces.nsIIOService);
	
	// Load the utilities required to access the local file system (required to write a forged certificate chain for the Crossbear-Server to a file)
	Components.utils.import("resource://gre/modules/FileUtils.jsm");
	
	// Initialize the member function references for the class prototype (like this it's only done once and not every time a instance of this object is created)
	if (typeof (_crossbear_protector_prototype_called) == 'undefined') {
		_crossbear_protector_prototype_called = true;

		/**
		 * This function check if the certificate that a connection uses should be trusted for that connection. If that is already known it cancels or accepts the connection.
		 * 
		 * If that is not yet known it contacts the Crossbear server and requests a certificate verification. As soon as the server replied, this function displays an UnknownCertDlg to the user and asks whether the certificate should be trusted.
		 * Based on the user's decision the original connection is either canceled or accepted.
		 * 
		 * @param channel The nsIChannel representing the connection
		 * @param serverCertChain The certificate chain of the connection
		 * @param serverCertHash The SHA256-hash of the certificate that should or should not be trusted when received from "host"
		 * @param hostIPPort The connection's host ("Hostname|IP|Port")
		 */
		Crossbear.CBProtector.prototype.getAndApplyTrustDecision = function getAndApplyTrustDecision(channel, serverCertChain, serverCertHash, hostIPPort) {
			
			// Check if the certificate has been seen for the domain. If yes: get the cached policy
			var cacheStatus = cbFrontend.cbtrustdecisioncache.checkValidity(serverCertHash, hostIPPort.split("|")[0], cbFrontend.cbeventobserver.checkCBServerOnly);
			
			// In case the conection was targeted for the Crossbear-Server but did not use the correct certificate: Warn the user and cancel the connection (also ask the user to send the certificate to the Crossbear-Team)
			if(cacheStatus == Crossbear.CBTrustDecisionCacheReturnTypes.CB_SERVER_NOT_VALID){
				
				self.handleMitM(channel, serverCertChain, hostIPPort);
			
			// In case the user considers the connection's certificate valid for this domain -> Load the page.
			} else if(cacheStatus == Crossbear.CBTrustDecisionCacheReturnTypes.OK || cacheStatus == Crossbear.CBTrustDecisionCacheReturnTypes.CB_SERVER_OK ){

				self.acceptConnection(channel, false);
			
			// In case the user considers the connection's certificate INVALID for this domain -> Abort the page loading
			} else if(cacheStatus == Crossbear.CBTrustDecisionCacheReturnTypes.NOT_VALID){
				
				self.rejectConnection(channel, false, hostIPPort);
			
			// If the certificate/domain combination was not found in the local cache initially: Request the server to verify the certificate
			} else if(cacheStatus == Crossbear.CBTrustDecisionCacheReturnTypes.NOT_IN_CACHE){
				
				// Suspend the loading of the page (and resume it after it is known whether the connection should be established or not)
				channel.suspend();
				
				self.requestVerification(channel, serverCertChain, serverCertHash, hostIPPort);
				
			// If the cacheStatus is not "OK", "NOT_VALID", "CB_SERVER_OK", "CB_SERVER_NOT_VALID" or "NOT_IN_CACHE" then something is seriously going wrong -> Rise an exception
			} else {
				
				cbFrontend.displayTechnicalFailure("CBProtector:getAndApplyTrustDecision: TrustDecisionCache returned unknown value:"+cacheStatus, true);
			}
		};
		
		/**
		 * This function adds a new CertVerificationRequest-object to the list of open requests. If it is the first request of its kind then the Crossbear server is contacted and a certificate verification is requested.
		 * 
		 * @param channel The nsIChannel representing the connection
		 * @param serverCertChain The certificate chain of the connection
		 * @param serverCertHash The SHA256-hash of the certificate that should or should not be trusted when received from "host"
		 * @param hostIPPort The connection's host ("Hostname|IP|Port")
		 */
		Crossbear.CBProtector.prototype.requestVerification = function requestVerification(channel, serverCertChain, serverCertHash, hostIPPort) {
			
			// Create a new CertVerificationRequest-object
			var request = {
				channel : channel,
				serverCertChain : serverCertChain,
				serverCertHash : serverCertHash,
				hostIPPort : hostIPPort
			};
			
			// Add it to the list of open requests
			self.requestsPending.push(request);
			
			// Check if it is the first request of its kind
			var isNewRequest = false;
			for ( var i = 0; i < self.requestsPending.length; i++) {

				// Go through all requests in the queue and compare them with the new request
				if (self.requestsPending[i].serverCertHash == request.serverCertHash && self.requestsPending[i].hostIPPort == request.hostIPPort) {
					
					// If they match the request then check if we found the very request that was created above. If that is the case then the request above is the first of its kind
					if(self.requestsPending[i].channel === request.channel){
						isNewRequest = true;
					}
					break;
				}
			}
			
			// If the request is the first request of its kind: contact the Crossbear server
			if(isNewRequest){
				
				self.requestVerificationFromServer(serverCertChain, serverCertHash, hostIPPort);
				
			}
		};
		
		/**
		 * Request a certificate verification from the Crossbear server
		 * 
		 * @param serverCertChain The certificate chain that should be verified
		 * @param serverCertHash The SHA256-hash of the certificate that should or should not be trusted when received from "host"
		 * @param hostIPPort The host from which the certificate chain was observed ("Hostname|IP|Port")
		 */
		Crossbear.CBProtector.prototype.requestVerificationFromServer = function requestVerificationFromServer(serverCertChain, serverCertHash, hostIPPort) {
			
			// Add an entry in the log
			cbFrontend.displayInformation("Requesting Verification for \""+ hostIPPort + "\" from the Crossbear server");

			// Create the CertVerifyRequest-message that should be sent
			var msg = new Crossbear.CBMessageCertVerifyRequest(serverCertChain, hostIPPort, (pps.resolve(ioService.newURI("https://"+ hostIPPort.split("|")[0], null, null),0) != null)?1:0);

			// Send the message to the server ...
			cbFrontend.cbnet.postBinaryRetrieveBinaryFromUrl("https://" + cbFrontend.cbServerName + "/verifyCert.jsp", cbFrontend.cbServerName + ":443", Crossbear.jsArrayToUint8Array(msg.getBytes()), self.certVerifyCallback, {serverCertChain: serverCertChain, serverCertHash: serverCertHash, hostIPPort : hostIPPort });
			
		};
		
		/**
		 * Add a new entry in the CBTrustDecisionCache for the host's certificate and domain according to the user's choice of trust and his/hers defaultCacheValidity.
		 * 
		 * @param serverCertHash The SHA256-hash of the certificate that should or should not be trusted when received from "host"
		 * @param hostIPPort The host from which the certificate chain was observed ("Hostname|IP|Port")
		 * @param trust true if the user want's the certificate to be trusted, otherwise false
		 */
		Crossbear.CBProtector.prototype.addCacheEntryDefaultValidity = function addCacheEntryDefaultValidity(serverCertHash, hostIPPort, trust) {
			// Get a timestamp for the current time
			var currentTimestamp = Math.round(new Date().getTime() / 1000);

			// Add a new entry in the CBTrustDecisionCache for the host's certificate and domain according to the user's choice of trust and his/hers tdcValidity.
			cbFrontend.cbtrustdecisioncache.add(serverCertHash, hostIPPort, trust, currentTimestamp + cbFrontend.getUserPref("protector.tdcValidity", "int"));
		};
		
		/**
		 * The user made a trust decision that should be applied to all pending connections and to all future connections. Therefore this function does two things:
		 * - adding the user's trust decision to the local trust decision cache
		 * - applying the user's trust decision to all pending connections
		 * 
		 * @param serverCertHash The SHA256-hash of the certificate that should or should not be trusted when received from "host"
		 * @param hostIPPort The host from which the certificate chain was observed ("Hostname|IP|Port")
		 * @param trust true if the user want's the certificate to be trusted, otherwise false
		 */
		Crossbear.CBProtector.prototype.applyNewTrustDecision = function applyNewTrustDecision(serverCertHash, hostIPPort, trust) {
		
			// Add the user's trust decision to the local trust decision cache
			self.addCacheEntryDefaultValidity(serverCertHash, hostIPPort.split("|")[0], trust?1:0);
			
			// Clone the request list
			var requestListCopy = Crossbear.clone(self.requestsPending);

			// Iterate over all of the requests
			for ( var i = requestListCopy.length-1; i >=0 ; i--) {

				// Check if the trust decision applies to them
				if (requestListCopy[i].serverCertHash == serverCertHash && requestListCopy[i].hostIPPort == hostIPPort) {
					
					// If it applies: Accept or reject the connection
					if(trust){
						
						self.acceptConnection(requestListCopy[i].channel, true);
						
					} else{
						
						self.rejectConnection(requestListCopy[i].channel, true, requestListCopy[i].hostIPPort);
						
					}
					
					requestListCopy.splice(i, 1);
					
				}
			}
			
			// Replace the list of requests with the modified one
			self.requestsPending = requestListCopy;
					
		};

		/**
		 * Accept all pending connections. 
		 * 
		 * Please note: This function does not modify the TDC!
		 */
		Crossbear.CBProtector.prototype.acceptAllPendingConnections = function acceptAllPendingConnections() {

			// Iterate over all of the requests
			for ( var i = self.requestsPending.length-1; i >=0 ; i--) {

				// Accept the connection
				self.acceptConnection(self.requestsPending[i].channel, true);

			}

		};

		
		/**
		 * Parse the server's response on a CertVerifyRequest. This response could be
		 * - No Response (because of a timeout)
		 * - A simple response that must possibly be displayed to the user
		 * - A response consisting of a normal response, and a piggy-backed HuntingTask (+PublicIPNotification, +CurrentServerTime )
		 * 
		 * This function will forward all piggy-backed HuntingTasks to the Hunter. Furthermore it will display a UnknownCertDlg if the user doesn't use the automatic-trust-setting or the server responded with a low rating. If the user DOES use that setting
		 * and the server responded with a high rating then an entry in the CBTrustDecisionCache is created automatically.
		 * 
		 * If a timeout occurred then a UnknownCertDlg will again be shown.
		 * 
		 * Please note: This function is a XMLHTTPRequest-callback-function
		 */
		Crossbear.CBProtector.prototype.certVerifyCallback = function certVerifyCallback() {

			// Check if the server's reply has entirely been received
			if ((this.readyState == 4) && (this.status == 200)) {

				// If yes: check if that reply actually contained data
				var output = this.response;
				if (output) {

					// Try to Decode the server's reply as an array of CBMessages
					var serverMessages = Crossbear.messageBuilder(new Uint8Array(output), cbFrontend);

					// Read the messages and store their content at the appropriate places
					for ( var i = 0; i < serverMessages.length; i++) {

						// Decode the CertVerifyResponse
						if (serverMessages[i].messageType == "CBMessageCertVerifyResult") {

							// Extract the rating
							var rating = serverMessages[i].getRating();

							// Check if the user activated automatic trust and what is the minimal rating for that
							var trustAutomatically = cbFrontend.getUserPref("protector.trustAutomatically", "bool");
							var ratingToTrustAutomatically = cbFrontend.getUserPref("protector.ratingToTrustAutomatically", "int");

							// If the user activated automatic trust and the rating is high enough -> create an entry in the cache
							if (trustAutomatically && rating > ratingToTrustAutomatically) {

								self.applyNewTrustDecision(this.cbCallBackParams.serverCertHash, this.cbCallBackParams.hostIPPort, true);
								continue;
							}

							/*
							 * If the user deactivated automatic trust or the rating was not high enough -> show an UnknownCertDlg-window
							 * 
							 * First: Create the parameters for that window
							 */ 
							var params = {
								inn : {
									cbFrontend : cbFrontend,
									rating : rating,
									ratingToTrustAutomatically : ratingToTrustAutomatically,
									judgment : serverMessages[i].getJudgments(),
									serverCertChain : this.cbCallBackParams.serverCertChain,
									serverCertHash : this.cbCallBackParams.serverCertHash,
									hostIPPort : this.cbCallBackParams.hostIPPort,
									wasTimeout : false
								},
								out : {}
							};

							// Second: Display it 
							window.openDialog("chrome://crossbear/content/gui/UnknownCertDlg.xul", "", "chrome,centerscreen,dependent=YES,dialog=YES,close=no", params);

						// A HuntingTask will be stored in and then executed by the CBHunter(WorkerThread)
						} else if (serverMessages[i].messageType == "CBMessageHuntingTask") {
							cbFrontend.cbhunter.addTask(serverMessages[i]);

						// The current server time will be stored in the cbFrontend
						} else if (serverMessages[i].messageType == "CBMessageCurrentServerTime") {
							cbFrontend.calcAndStoreCbServerTimeDiff(serverMessages[i].getCurrentServerTime());

						// The PublicIP will be stored in the CBHunter(WorkerThread)
						} else if (serverMessages[i].messageType == "CBMessagePublicIPNotif") {
							cbFrontend.cbhunter.addPublicIP(serverMessages[i]);

						} else {
							cbFrontend.displayTechnicalFailure("CBProtector:certVerifyCallback: received unknown message from server.", true);
						}
					}

				} else {
					cbFrontend.displayTechnicalFailure("CBProtector:certVerifyCallback: received empty reply from cbServer.", true);
				}

				// In case the server could not be contacted because of a timeout: Call the handleTimeout-function
			} else if ((this.readyState == 4) && (this.status == 0)) {
				cbFrontend.displayTechnicalFailure("CBProtector:certVerifyCallback: could not connect to cbServer (connection timed out)!", false);

				/*
				 * If the server could not be contacted, user interaction is necessary -> show an UnknownCertDlg-window
				 * 
				 * First: Create the parameters for that window
				 */ 
				var params = {
					inn : {
						cbFrontend : cbFrontend,
						rating : "X",
						ratingToTrustAutomatically : "X",
						judgment : "Unable to connect to the Crossbear server. This could have a lot of reasons. One of them is that you are under attack by a powerful attacker. Please be careful!",
						serverCertChain : this.cbCallBackParams.serverCertChain,
						serverCertHash : this.cbCallBackParams.serverCertHash,
						hostIPPort : this.cbCallBackParams.hostIPPort,
						wasTimeout : true
					},
					out : {}
				};

				// Second: Display it 
				window.openDialog("chrome://crossbear/content/gui/UnknownCertDlg.xul", "", "chrome,centerscreen,dependent=YES,dialog=YES,close=no", params);

				// In case the server could not be contacted because an error other than a timeout occurred: Throw an exception!
			} else if ((this.readyState == 4)) {
				cbFrontend.displayTechnicalFailure("CBProtector:certVerifyCallback: could not connect to cbServer (HTTP-STATUS: " + this.status + ":" + this.statusText + ")!", true);
			}

		};
		
		/**
		 * Accept a connection (usually because its certificate has been approved by the user)
		 * 
		 * @param channel The nsIChannel representing the connection
		 * @param isSuspended A flag indicating whether the connection has been suspended earlier
		 */
		Crossbear.CBProtector.prototype.acceptConnection = function acceptConnection(channel, isSuspended) {
			
			// If the connection has been suspended: resume it. If not do not do anything ;)
			if(isSuspended){
				channel.resume();
			}
			
		};
		
		/**
		 * Reject a connection (usually because its certificate has been disapproved by the user)
		 * 
		 * @param channel The nsIChannel representing the connection
		 * @param isSuspended A flag indicating whether the connection has been suspended earlier
		 * @param hostIPPort The connection's host ("Hostname|IP|Port")
		 */
		Crossbear.CBProtector.prototype.rejectConnection = function rejectConnection(channel, isSuspended, hostIPPort) {
			
			// Display an information that a connection was canceled
			cbFrontend.displayInformation("You tried to access " + hostIPPort.split("|")[0] + " with a certificate you don't trust. This attempt was canceled.",0);
			
			// If the connection was suspended earlier: resume it
			if(isSuspended){
				channel.resume();
			}
			
			// Cancel the connection attempt
			channel.cancel(Components.results.NS_BINDING_SUCCEEDED);
	
		};
		
		/**
		 * This function is called if a connection that was directed for the Crossbear server did not use the expected certificate. This is considered to be a MitM attack. Consequently, the user is notified about this attack and is asked to send the
		 * certificate chain that the Crossbear server seems to use to the Crossbear team.
		 * 
		 * @param channel The nsIChannel representing the connection
		 * @param serverCertChain The certificate chain of the connection
		 * @param hostIPPort The connection's host ("Hostname|IP|Port")
		 */
		Crossbear.CBProtector.prototype.handleMitM = function handleMitM(channel, serverCertChain, hostIPPort) {
			
			// Get the certificate chain that the Crossbear-Server seems to use and convert it into a string
			var base64CertChain = Crypto.util.bytesToBase64(Crossbear.implodeArray(serverCertChain));
		    
			// Create a file in the temp-directory
			var tempFile = FileUtils.getFile("TmpD", ["crossbear.certchain.txt"]);
			
			// Write the certificate chain into that file
			Crossbear.writeStringToFile(base64CertChain,tempFile);
			
			// Display the warning dialog to the user and ask him/her to send the certificate chain to the Crossbear-Team
			var emailLinkText = "mailto:crossbear@pki.net.in.tum.de?subject=Observation%20strange%20certificate%20chain%20for%20the%20Crossbear-Server&body=Hey%20Crossbear-Team,%0D%0A%0D%0AI%20observed%20a%20strange%20certificate%20chain%20for%20the%20Crossbear-Server("+hostIPPort+")%20on%20"+new Date().toGMTString() +"%0D%0A%0D%0A#########################################################################################%0D%0ANOTE%20TO%20SENDER:%20PLEASE%20ATTACH%20THE%20FILE%20CONTAINING%20THE%20CERTIFICATE%20CHAIN!%20YOU%20FIND%20IT%20AT%0D%0A%0D%0A"+tempFile.path+"%0D%0A%0D%0A#########################################################################################%0D%0A%0D%0ABest%20regards,%0D%0A%0D%0AA%20friendly%20Crossbear-User";
			var mitmWarningXML = document.implementation.createDocument(null, "p", null);
                        var mitmWarning = mitmWarningXML.createTextNode("The Crossbear server sent an unexpected certificate. It is VERY LIKELY that you are under attack by a man-in-the-middle! This means an attacker can potentially read and alter everything you send from your browser!");
			var brElement = mitmWarningXML.createElement("br");
			var emailRequest = mitmWarningXML.createElement("a");
			emailRequest.setAttribute("style", "text-decoration:underline");
                        emailRequest.setAttribute("href", {emailLinkText});
                        var mitmWarningHeader = mitmWarningXML.createTextNode("You could do the research community a big favor by ");
			var emailText = mitmWarningXML.createTextNode(" sending an e-mail ");
                        var mitmWarningTrailer = mitmWarningXML.createTextNode(" to the Crossbear team.");
			emailRequest.appendChild(emailText);
			mitmWarningXML.appendChild(mitmWarning);
			mitmWarningXML.appendChild(brElement);
			mitmWarningXML.appendChild(mitmWarningHeader);
			mitmWarningXML.appendChild(emailRequest);
			mitmWarningXML.appendChild(mitmWarningTrailer);
			cbFrontend.warnUserAboutBeingUnderAttack(mitmWarningXML,5);
			
			// Cancel the connection attempt
			channel.cancel(Components.results.NS_BINDING_SUCCEEDED);
		};

	}

};
