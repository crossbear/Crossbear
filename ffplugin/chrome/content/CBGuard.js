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
 * The CBGuard-class is the local system's interface to the server's certificate verification functionality. When asked to perform a certificate verification this class will forward the request to the server and parse its answer. If the user chose to
 * use the automatic-trust-setting and the server responds with a high rating then the only thing that is done is a Cache-update. In all other cases a UnknownCertDlg will be displayed.
 * 
 * If the same request is uttered more than once while the original one is still to process (i.e. in the queue), then all duplicate requests will be ignored. Although this does not prevent duplicates completely it reduces their number significantly
 * and therefore increases the overall performance of the Crossbear system.
 * 
 * Please Note: This class maintains an internal queue of CertVerificationRequests to filter duplicates. The queue will only work as long as this class is accessed by a single thread only. Therefore it is assumed that there is only one GUI-Thread,
 * which is true to my best knowledge.
 * 
 * @param cbFrontend The cbFrontend-class that will be used to display information/errors to the user and to read the user preferences and settings.
 * 
 * @author Thomas Riedmaier
 */
function CBGuard(cbFrontend) {
	this.cbFrontend = cbFrontend;

	// The list of all CertificateVerificationRequests that are to be done. This list does not include any duplicates for performance reasons (see class description).
	this.requestsPending = [];

	// Flag indicating if there is currently a request processed or if the guard is idle
	this.currentlyRequesting = false;

	// "this" does not always point to THIS object (especially in callback functions). Therefore I use the "self" variable to hold a handle on THIS object
	var self = this;

	// Initialize the member function references for the class prototype (like this it's only done once and not every time a instance of this object is created)
	if (typeof (_cbguard_prototype_called) == 'undefined') {
		_cbguard_prototype_called = true;

		/**
		 * Add a new entry in the CBCertificateCache for the host's certificate and domain according to the user's choice of trust and his/hers defaultCacheValidity.
		 * 
		 * @param certHash The SHA256-hash of the certificate that should or should not be trusted when received from "host"
		 * @param host The host that should or should not be trusted when sending a certificate with hash "hash"
		 * @param trust "1" if the user want's the certificate to be trusted, else "0"
		 */
		CBGuard.prototype.addCacheEntryDefaultValidity = function addCacheEntryDefaultValidity(certHash, host, trust) {
			// Get a timestamp for the current time
			var currentTimestamp = Math.round(new Date().getTime() / 1000);

			// Add a new entry in the CBCertificateCache for the host's certificate and domain according to the user's choice of trust and his/hers defaultCacheValidity.
			cbFrontend.cbcertificatecache.add(certHash, host, trust, currentTimestamp + cbFrontend.getUserPref("guard.certCacheDefaultValidity", "int"));
		};

		/**
		 * Parse the server's response on a CertVerifyRequest. This response could be
		 * - No Response (because of a timeout)
		 * - A simple response that must possibly be displayed to the user
		 * - A response consisting of a normal response, and a piggy-backed HuntingTask (+PublicIPNotification, +CurrentServerTime )
		 * 
		 * This function will forward all piggy-backed HuntingTasks to the Hunter. Furthermore it will display a UnknownCertDlg if the user doesn't use the automatic-trust-setting or the server responded with a low rating. If the user DOES use that setting
		 * and the server responded with a high rating then an entry in the CBCertificateCache is created automatically.
		 * 
		 * If a timeout occurred then a UnknownCertDlg will again be shown.
		 * 
		 * Please note: This function is a XMLHTTPRequest-callback-function
		 */
		CBGuard.prototype.certVerifyCallback = function certVerifyCallback() {

			// Check if the server's reply has entirely been received
			if ((this.readyState == 4) && (this.status == 200)) {

				// If yes: check if that reply actually contained data
				var output = this.response;
				if (output) {

					// Try to Decode the server's reply as an array of CBMessages
					var serverMessages = messageBuilder(new Uint8Array(output), cbFrontend);

					// Read the messages and store their content at the appropriate places
					for ( var i = 0; i < serverMessages.length; i++) {

						// Decode the CertVerifyResponse
						if (serverMessages[i].constructor.name == "CBMessageCertVerifyResult") {

							// Extract the rating
							var rating = serverMessages[i].getRating();

							// Check if the user activated automatic trust and what is the minimal rating for that
							var trustAutomatically = cbFrontend.getUserPref("guard.trustAutomatically", "bool");
							var ratingToTrustAutomatically = cbFrontend.getUserPref("guard.ratingToTrustAutomatically", "int");

							// If the user activated automatic trust and the rating is high enough -> create an entry in the cache
							if (trustAutomatically && rating > ratingToTrustAutomatically) {

								self.addCacheEntryDefaultValidity(self.requestsPending[0].certHash, self.requestsPending[0].host.split("|")[0], 1);
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
									certBytes : self.requestsPending[0].certBytes,
									certHash : self.requestsPending[0].certHash,
									host : self.requestsPending[0].host,
									wasTimeout : false
								},
								out : {}
							};

							// Second: Display it 
							window.openDialog("chrome://crossbear/content/gui/UnknownCertDlg.xul", "", "chrome,centerscreen,dependent=YES,dialog=YES,close=no", params);

						// A HuntingTask will be stored in and then executed by the CBHunter(WorkerThread)
						} else if (serverMessages[i].constructor.name == "CBMessageHuntingTask") {
							cbFrontend.cbhunter.addTask(serverMessages[i]);

						// The current server time will be stored in the cbFrontend
						} else if (serverMessages[i].constructor.name == "CBMessageCurrentServerTime") {
							cbFrontend.calcAndStoreCbServerTimeDiff(serverMessages[i].getCurrentServerTime());

						// The PublicIP will be stored in the CBHunter(WorkerThread)
						} else if (serverMessages[i].constructor.name == "CBMessagePublicIPNotif") {
							cbFrontend.cbhunter.addPublicIP(serverMessages[i]);

						} else {
							cbFrontend.displayTechnicalFailure("CBGuard:certVerifyCallback: received unknown message from server.", true);
						}
					}

					// If there is another request pending-> Execute it (i.e. forward it to the server)
					self.continueWithNextRequest();

				} else {
					cbFrontend.displayTechnicalFailure("CBGuard:certVerifyCallback: received empty reply from cbServer.", true);
				}

				// In case the server could not be contacted because of a timeout: Call the handleTimeout-function
			} else if ((this.readyState == 4) && (this.status == 0)) {
				cbFrontend.displayTechnicalFailure("CBGuard:certVerifyCallback: could not connect to cbServer (connection timed out)!", false);

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
						judgment : "Unable to connect to the Crossbear server. This could be caused have a lot of reasons. One of them is that you are under attack by a powerful attacker.",
						certBytes : self.requestsPending[0].certBytes,
						certHash : self.requestsPending[0].certHash,
						host : self.requestsPending[0].host,
						wasTimeout : true
					},
					out : {}
				};

				// Second: Display it 
				window.openDialog("chrome://crossbear/content/gui/UnknownCertDlg.xul", "", "chrome,centerscreen,dependent=YES,dialog=YES,close=no", params);

				// If there is another request pending-> Execute it (i.e. forward it to the server)
				self.continueWithNextRequest();

				// In case the server could not be contacted because an error other than a timeout occurred: Throw an exception!
			} else if ((this.readyState == 4)) {
				cbFrontend.displayTechnicalFailure("CBGuard:certVerifyCallback: could not connect to cbServer (HTTP-STATUS: " + this.status + ":" + this.statusText + ")!", true);
			}

		};

		/**
		 * Remove the current CertVerificationRequest from the todo-list and go on with the next one
		 */
		CBGuard.prototype.continueWithNextRequest = function continueWithNextRequest() {
			self.requestsPending.shift();
			self.executeFirstPendingRequest();
		};

		/**
		 * Get the oldest CertVerificationRequest from the todo-list. If there is any: execute it (i.e. forward it to the server)
		 */
		CBGuard.prototype.executeFirstPendingRequest = function executeFirstPendingRequest() {

			// Make sure that there is at least one request on the todo-list. If not: terminate the execution of the CertVerificationRequest list.
			if (self.requestsPending.length == 0) {

				// If that's not true return
				self.currentlyRequesting = false;
				return;
			}

			// Create the CertVerifyRequest-message that should be sent
			var msg = new CBMessageCertVerifyRequest(self.requestsPending[0].certBytes, self.requestsPending[0].host);

			// Send the message to the server ...
			cbFrontend.cbnet.postBinaryRetrieveBinaryFromUrl("https://" + cbFrontend.cbServerName + "/verifyCert.jsp", cbFrontend.cbServerName + ":443", jsArrayToUint8Array(msg.getBytes()), self.certVerifyCallback, null);

		};

		/**
		 * Request the verification of a Certificate/domain-combination from the server. To do so, add a CertVerificationRequest to the current CertVerificationRequest-todo-list and in case it is the first one: Start executing it. In case the same
		 * CertVerificationRequest is already waiting in the Todo-list don't add it again.
		 * 
		 * @param certBytes The RAW-Bytes of the certificate that should or should not be trusted when received from "host" in DER-encoding
		 * @param certHash The SHA256-hash of the certificate that should or should not be trusted when received from "host"
		 * @param host The host that should or should not be trusted when sending a certificate with hash "hash"
		 */
		CBGuard.prototype.requestVerification = function requestVerification(certBytes, certHash, host) {

			// Create a new CertVerificationRequest-object
			var request = {
				certBytes : certBytes,
				certHash : certHash,
				host : host
			};

			// Check if the CertVerificationRequest is actually new or already in queue
			var isNew = true;
			for ( var i = 0; i < self.requestsPending.length; i++) {

				// Go through all requests in the queue and compare them with the new request
				if (self.requestsPending[i].certHash == request.certHash && self.requestsPending[i].host == request.host) {
					isNew = false;
					break;
				}
			}

			// Only if the request is new: Add it to the todo-list
			if (isNew) {
				self.requestsPending.push(request);
			}

			// In case there is a CertificateVerificationRequest pending: execute it
			self.verifyRequestIfNoneIsPending();
		};

		/**
		 * Check if there is a currently active CertVerificationRequest execution. If there is none start executing the CertVerificationRequest-list
		 */
		CBGuard.prototype.verifyRequestIfNoneIsPending = function verifyRequestIfNoneIsPending() {

			if (!self.currentlyRequesting) {
				self.currentlyRequesting = true;
				self.executeFirstPendingRequest();
			}
		};

	}

}