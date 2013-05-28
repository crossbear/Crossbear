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
 * The CBHunter-class has two functionalities. The first one is to relay information (like NewHuntingTasks, NewPublicIPs, NewServerIPs, CBHunterWorkerErrors ...) to and from the CBHunterWorkerThread. The second functionality is to provide all
 * functions to the CBHunterWorkerThread that either need to access privileged operations (e.g. database, DNS, ...) or that can be done in an asynchronous way.
 * 
 * Additionally the CBHunter-class provides the functionality to launch and to terminate the CBHunterWorkerThread. 
 * 
 * @param cbFrontend The cbFrontend-class that will be used to display information/errors to the user and to read the user preferences and settings.
 * 
 * @author Thomas Riedmaier
 */
Crossbear.CBHunter = function (cbFrontend) {
	this.cbFrontend = cbFrontend;
	
	// The CBHunterWorkerThread to which all information will be forwarded and which will then execute the HuntingTasks
	this.worker = null;
		
	/*
	 * If != null the receiveCBServerIPsCallback-function will be called after the execution of the receiveCBServerIPs-function. This is necessary in order to transfer the control-flow back to the class that called the
	 * requestCBServerIPs-function while at the same time providing the server's IPs to it.
	 */
	this.receiveCBServerIPsCallback = null;

	// "this" does not always point to THIS object (especially in callback functions). Therefore I use the "self" variable to hold a handle on THIS object
	var self = this;

	// Initialize the member function references for the class prototype (like this it's only done once and not every time a instance of this object is created)
	if (typeof (_crossbear_hunter_prototype_called) == 'undefined') {
		_crossbear_hunter_prototype_called = true;

		/**
		 * Initialize the CBHunter and the CBHunterWorkerThread
 		 */
		Crossbear.CBHunter.prototype.init = function init() {
			
			// First: Check if the Hunter is already initialized. If not: initialize it
			if (self.worker == null) {

				// Create the worker-thread
				self.worker = new ChromeWorker("chrome://crossbear/content/CBHunterWorkerThread.js");

				// Set the callback function (i.e. the function that will receive all Events sent by the worker-thread)
				self.worker.onmessage = self.wtcallback;

				// Check if the current system is a Windows or a Unix/Linux system
				var osIsWin = Crossbear.startsWith(navigator.platform.toUpperCase(), "WIN");
				
				// Create a CBHunterWorkerInitEvent that contains all parameters related to Hunting (read them from the user's preferences) and the paths to the native libraries (different depending on the current operating system)
				var wie = new Crossbear.CBHunterWorkerInitEvent(cbFrontend.getUserPref("hunter.tracerouteSamplesPerHop", "int"), cbFrontend.getUserPref("hunter.tracerouteMaxHops", "int"), Crossbear.getLibPaths(cbFrontend, osIsWin), osIsWin, cbFrontend.getUserPref("hunter.publicIPcacheValidity", "int"), cbFrontend.getUserPref("hunter.serverIPcacheValidity", "int"));
				
				// Initialize the CBHunterWorkerThread with that Event
				self.worker.postMessage(wie);

			}
		};
		
		/**
		 * The Hunter's Event-Dispatcher. The Events that are expected are defined at the very beginning of the CBHunterWorkerThread-file. All others will generate a critical failure.
		 * 
		 * @param event A nsIWorkerMessageEvent that is sent from the CBHunterWorkerThread using the postMessage() function. The event.data field is expected to be a Event defined within the CBEvents-file.
		 */
		Crossbear.CBHunter.prototype.wtcallback = function wtcallback(event) {

			// Look on the eventtype of the Event an perform actions according to it
			if (event.data.eventtype) {
				if (event.data.eventtype == "CBHunterWorkerNewPublicIPRequest") {
					self.requestPublicIP(event.data.serverIP, event.data.ipVersion, null);
					return;

				} else if (event.data.eventtype == "CBHunterWorkerNewServerIPsRequest") {
					self.requestCBServerIPs(null);
					return;
					
				} else if (event.data.eventtype == "CBHunterWorkerServerTimeRequest") {
					// Estimate the current server time and send it to the CBHunterWorkerThread
					self.worker.postMessage(new Crossbear.CBHunterWorkerServerTimeReply(cbFrontend.getServerTime()));
					return;
					
				} else if (event.data.eventtype == "CBHunterWorkerDBStoreRequest") {
					self.storeHuntingTaskResultLocal(event.data.taskID, event.data.publicIP, event.data.serverTimeOfExecution);
					return;
					
				} else if (event.data.eventtype == "CBHunterWorkerHuntingResults") {
					
					// Concatenate the bytes of the HuntingTaskResults into a single byte[]
					var replyRawData = Crossbear.implodeArray(event.data.results);
					
					// Try to send the byte[]-representation of the HuntingTaskResult-array to the Crossbear Server
					cbFrontend.displayInformation("Sending "+event.data.results.length+" results to the Crossbear Server ...");
					cbFrontend.cbnet.postBinaryRetrieveBinaryFromUrl("https://" + cbFrontend.cbServerName + "/reportHTResults.jsp", cbFrontend.cbServerName + ":443", Crossbear.jsArrayToUint8Array(replyRawData),self.sendHuntingTaskResultsCallback,{ replyRawData: replyRawData, numOfFailedAttempts : 0});
					return;

				} else if (event.data.eventtype == "CBHunterWorkerError") {
					cbFrontend.displayTechnicalFailure(event.data.what, event.data.critical);
					return;
				} else if (event.data.eventtype == "CBHunterWorkerInformation") {
					cbFrontend.displayInformation(event.data.what);
					return;
				}
			}
			cbFrontend.displayTechnicalFailure("CBHunter:wtcallback: received unknown event: " + event.data.eventtype, true);

		};
		
		/**
		 * Terminate and destroy the object's CBHunterWorkerThread (in case it is not active: do nothing)
		 */
		Crossbear.CBHunter.prototype.terminate = function terminate() {
			if (self.worker != null) {
				self.worker.terminate();
				self.worker = null;
			}
		};
		
		/**
		 * Add a new HuntingTask to the HuntingTask-Todo-List of the CBHunterWorkerThread.
		 * 
		 * @param CBMessageHuntingTask A CBMessageHuntingTask-object that represents the Task that should be added to the todo-list
		 */
		Crossbear.CBHunter.prototype.addTask = function addTask(CBMessageHuntingTask) {
			
			cbFrontend.displayInformation("Adding execution of task " + CBMessageHuntingTask.getTaskID()+ " to local \"todo\"-list.");
			
			// Convert the CBMessageHuntingTask-message into a CBHunterWorkerNewTask-Event so it can be send to the CBHunterWorkerThread ...
			var newTask = new Crossbear.CBHunterWorkerNewTask(CBMessageHuntingTask.getTaskID(), CBMessageHuntingTask.getIPVersion(),CBMessageHuntingTask.getAlreadyKnownHashes(), CBMessageHuntingTask.getTargetIP(), CBMessageHuntingTask.getTargetPort(), CBMessageHuntingTask.getHostname());
	
			// ... and send it.
			self.worker.postMessage(newTask);
		};
	
		/**
		 * Notify the CBHunterWorkerThread about a current PublicIP of the system (version 4 or 6)
		 * 
		 * @param CBMessagePublicIPNotif A CBMessagePublicIPNotif-object that represents the PublicIP that has been observed for this client by the Crossbear server
		 */
		Crossbear.CBHunter.prototype.addPublicIP = function addPublicIP(CBMessagePublicIPNotif) {	
			
			cbFrontend.displayInformation("Crossbear server sent a new public ip: "+CBMessagePublicIPNotif.getPublicIP() + "(verified by "+ Crypto.util.bytesToBase64(CBMessagePublicIPNotif.getHMac()) +")");
			
			// Convert the CBMessagePublicIPNotif-message into a CBHunterWorkerNewPublicIP-Event so it can be send to the CBHunterWorkerThread ...
			var newIP = new Crossbear.CBHunterWorkerNewPublicIP(CBMessagePublicIPNotif.getIPVersion(),CBMessagePublicIPNotif.getPublicIP(), CBMessagePublicIPNotif.getHMac(), Math.round(new Date().getTime() / 1000));
			
			// ... and send it.
			self.worker.postMessage(newIP);
		};

		/**
		 * Contact the Crossbear server and ask for the current system's PublicIP of a specific version. This is done by connecting to the Crossbear server using that specific version of the IP-Protocol and thus giving the Crossbear server the
		 * possibility to generate a PublicIPNotification for that IP-version. Since there is no way to tell a XMLHTTPRequest which IP to use for a domain, the connection has to be made to the IP itself. This in turn makes the usage of HTTPS
		 * impossible (a SSL-connection to an IP will generate an exception since the certificate verification fails). Sending the PublicIP over a unprotected connection is not a good idea either because of the following scenario:
		 * 
		 * An attacker takes control over a DNS server and claims that his IPv4 is Crossbear's PublicIPv4-Address. Then he contacts the Crossbear server to get a PublicIPNotification-message with a valid HMAC. After that he distributes that message to all
		 * Crossbear clients that want to know their PublicIP. Since all of these clients will then generate HuntingTaskResults with the same (wrong) PublicIP a serious damage to the Crossbear-database is done.
		 * 
		 * To prevent this scenario from happening the PublicIPNotification-message is concatenated with its hash and then encrypted with a AES-key that is only known by the client that wants to know its PublicIP and the Crossbear server. This message can't
		 * be forged by an attacker anymore. Moreover it can trivially be checked for tampering by the Crossbear client.
		 * 
		 * The question remaining is how to generate a AES key that is only known to the Crossbear server and a single Crossbear client. The answer to this is "Generate a AES-key every time you connect to the Crossbear server and encrypt it with the server's
		 * public RSA-key. Then send the result to the server as a PublicIPNotifRequest."
		 * 
		 * All of this is done within this function. The handling of the server's reply is done in the receivePublicIP-function.
		 * 
		 * @param serverIP A IP of the Crossbear server of the same version for which the PublicIP should be looked up
		 * @param ipVersion The IPVersion of the serverIP
		 * @param callback The function that will be executed after the receivePublicIP-function has finished and the systems publicIP is known
		 */
		Crossbear.CBHunter.prototype.requestPublicIP = function requestPublicIP(serverIP, ipVersion, callback) {
			
			// Genereate a random AES256-key
			var currentAESKey = Crossbear.generate256BitAESKey();
			
			// Encrypt it with RSA/OAEP-padding using the Crossbear server's public key
			var paddedAESKey = Crossbear.RSA.OAEP.padBlock(currentAESKey,0,currentAESKey.length);
			
			// Then generate a CBMessagePublicIPNotifRequest containing the encrypted AES-key
			var publicIPNotifRequest = new Crossbear.CBMessagePublicIPNotifRequest(Crossbear.RSA.RSAencrypt(self.cbFrontend.ServerRSAKeyPair, paddedAESKey));

			// Finally send it to the Crossbear server. In order to be able to parse the server's reply, the callback-function of the XMLHTTPRequest (which is the receivePublicIP-function) must know the generated AES key. Therefore the it is passed within the callBackParams-object
			if (ipVersion == 4) {
				cbFrontend.cbnet.postBinaryRetrieveBinaryFromUrl("http://" + serverIP + ":80/getPublicIP.jsp", cbFrontend.cbServerName + ":80", Crossbear.jsArrayToUint8Array(publicIPNotifRequest.getBytes()), self.receivePublicIP,{ callback: callback, currentAESKey : currentAESKey});
			} else if (ipVersion == 6) {
				cbFrontend.cbnet.postBinaryRetrieveBinaryFromUrl("http://[" + serverIP + "]:80/getPublicIP.jsp", cbFrontend.cbServerName + ":80", Crossbear.jsArrayToUint8Array(publicIPNotifRequest.getBytes()), self.receivePublicIP,{ callback: callback, currentAESKey : currentAESKey});
			} else {
				cbFrontend.displayTechnicalFailure("CBHunter:requestPublicIP: Invalid ipVersion", true);
			}
		};

		/**
		 * This is the callback-function of the requestPublicIP-function. Thus it will be called when the Crossbear server sent a AES-encrypted PublicIPNotification-message. The function will decrypt the message and verify its integrity using the
		 * Message's hash that is sent along with the message. If that worked, the message is decoded and the addPublicIP-function is called for the IP contained within the message. Finally the callback-function that was passed to the
		 * requestPublicIP-function will be called.
		 * 
		 * Please note: This function is a XMLHTTPRequest-callback-function
		 */
		Crossbear.CBHunter.prototype.receivePublicIP = function receivePublicIP() {

			// Check if the server's reply has entirely been received
			if ((this.readyState == 4) && (this.status == 200)) {
				
				// If yes: check if that reply actually contained data
				var output = this.response;
				if (output) {

					// If yes: decrypt the reply using the AES key
					var encryptedServerResponse = Crossbear.uint8ArrayToJSArray(new Uint8Array(output));
					var plaintext = Crypto.AES.decrypt(encryptedServerResponse, this.cbCallBackParams.currentAESKey, {
						mode : new Crypto.mode.CBC(Crypto.pad.pkcs7),
						asBytes : true
					});

					// Check the decrypted plaintext for validity using the Hash that was sent along with it
					var supposedHash = plaintext.splice(plaintext.length - 32, 32);
					var actualHash = Crypto.SHA256(plaintext, {
						asBytes : true
					});
					
					// If somebody tampered with the data: Warn the user!
					if (!Crossbear.arrayCompare(supposedHash, actualHash)) {
					        var tamperWarningXML = document.implementation.createDocument(null, "p", null);
                                                var tamperWarning = tamperWarningXML.createTextNode("Your system is under attack! Somebody modified the datatransfer between the Crossbear server and your system.");
                    				tamperWarningXML.appendChild(tamperWarning);
						cbFrontend.warnUserAboutBeingUnderAttack(tamperWarningXML,5);
						cbFrontend.displayTechnicalFailure("CBHunter:receivePublicIP: received invalid input: "+plaintext+supposedHash+":"+actualHash, true);
						return;
					}

					// If the verification was successful cast the plaintext into a CBMessage-array
					var decodedMessages = Crossbear.messageBuilder(Crossbear.jsArrayToUint8Array(plaintext),cbFrontend);
					
					// If the message[] has more than one element then something went wrong
					if(decodedMessages.length != 1){
						cbFrontend.displayTechnicalFailure("CBHunter:receivePublicIP: received more than one message input!", true);
						return;
					}
					
					// If the CBMessage that has been received is not a CBMessagePublicIPNotif then something went wrong
					if(decodedMessages[0].messageType  != "CBMessagePublicIPNotif"){
						cbFrontend.displayTechnicalFailure("CBHunter:receivePublicIP: received a message of unexpected type!", true);
						return;
					}
					
					// If nothing went wrong: Store the PublicIP
					self.addPublicIP(decodedMessages[0]);

					// In case a callback-function was specified transfer the control-flow to it
					if(this.cbCallBackParams.callback != null){

						this.cbCallBackParams.callback(decodedMessages[0].getPublicIP());
						
					}
					return;

				} else {
					cbFrontend.displayTechnicalFailure("CBHunter:receivePublicIP: received empty reply from cbServer when asking for PublicIP!", true);
					return;
				}
			} else if ((this.readyState == 4) && (this.status == 0)) { 
				cbFrontend.displayTechnicalFailure("CBHunter:receivePublicIP: could not connect to cbServer (connection timed out)!", false);
				
				// In case a callback-function was specified transfer the control-flow to it
				if(this.cbCallBackParams.callback != null){

					this.cbCallBackParams.callback("");
					
				}
				return;
			} else if ((this.readyState == 4)) {
				cbFrontend.displayTechnicalFailure("CBHunter:receivePublicIP: could not connect to cbServer (HTTP-STATUS: "+this.status+":"+this.statusText+")!", true);
				return;
			}

		};

		/**
		 * Request a DNS-resolution for the domain-name of the Crossbear sever. This function will just request the resolution. The result of that resolution will be passed to the receiveCBServerIPs-function which will then parse it. After it
		 * finished, it will call the callback-function that is passed to the requestCBServerIPs-function.
		 * 
		 * @param callback The function that will be executed after the receiveCBServerIPs-function has finished and Crosssbear's IPs (both version 4 and 6) are known
		 */
		Crossbear.CBHunter.prototype.requestCBServerIPs = function requestCBServerIPs(callback) {
			// Remember the callback function (won't be overwritten by a null-value and there is only one piece of code that calls it with a value != null)
			if(callback != null){
				self.receiveCBServerIPsCallback = callback;
			}
			
			//Request the DNS-resolution
			cbFrontend.cbnet.requestServerDNS(cbFrontend.cbServerName, self.receiveCBServerIPs);
		};

		/**
		 * Receive the result of a request for a DNS-resolution for the domain-name of the Crossbear sever. This function needs to comply to the nsIDNSListener-interface and therefore has a onLookupComplete-subfunction that does all the work.
		 * 
		 * The function parses all of the DNS-records that were found for the Crossbear server and stores (at most) one IPv4-address and one IPv6-address. These are then passed to the CBHunterWorkerThread through a CBHunterWorkerNewServerIPs-Event.
		 * Finally the callback-function that was passed to the requestCBServerIPs-function will be called.
		 * 
		 * @param see http://www.oxymoronical.com/experiments/apidocs/platform/1.9.1/interface/nsIDNSListener
		 */
		Crossbear.CBHunter.prototype.receiveCBServerIPs = function receiveCBServerIPs() {};
		Crossbear.CBHunter.prototype.receiveCBServerIPs.onLookupComplete = function(aRequest, aRecord, aStatus) {

			// There is no guarantee that IPs for both IP-versions will be observed. Therefore, initialize the serverIPs to "" 
			var serverIPv4 = "";
			var serverIPv6 = "";

			// Are there known records for the Crossbear server?
			if (aRecord != null) {

				// If yes: Parse them and store one IPv4 and one IPv6 address (if possible)
				while (aRecord.hasMore()) {
					
					// Get the records one by one
					var currentAddr = aRecord.getNextAddrAsString();
					
					// Check if it's a IPv4-Address
					if (currentAddr.match(Crossbear.ipv4Regex)) {
						serverIPv4 = currentAddr;
						
					// Check if it's a IPv6-Address
					} else if (currentAddr.match(Crossbear.ipRegex)) {
						serverIPv6 = currentAddr;
						
					// If it's neither then something went wrong
					} else {
						var dnsWarningXML = document.implementation.createDocument(null, "p", null);
						// TODO: actually output {currentAddr}
						var dnsWarning = dnsWarningXML.createTextNode("Your DNS server generates generates invalid DNS entries.");
						dnsWarningXML.appendChild(dnsWarning);
						cbFrontend.warnUserAboutBeingUnderAttack(dnsWarningXML,5);
						cbFrontend.displayTechnicalFailure("CBHunter:receiveCBServerIPs: parsing DNS entry failed: "+currentAddr, true);
					}
				}
				
				// Generate a new CBHunterWorkerNewServerIPs-Event containing the server's IPs that have just been observed
				var newServerIP = new Crossbear.CBHunterWorkerNewServerIPs(serverIPv4,serverIPv6,Math.round(new Date().getTime() / 1000));
				
				// Send that Event to the CBHunterWorkerThread
				self.worker.postMessage(newServerIP);
				
				
				// In case a callback-function was specified transfer the control-flow to it
				if(self.receiveCBServerIPsCallback != null){
		
					var callback = self.receiveCBServerIPsCallback;
					self.receiveCBServerIPsCallback = null;
					callback(serverIPv4,serverIPv6);
					
				}
			} else {
				cbFrontend.displayTechnicalFailure("CBHunter:receiveCBServerIPs: receiving DNS entry for CBServer failed: " + aStatus, true);
			}
		};

		/**
		 * Store the fact of the successful execution of a HuntingTask in the performedTasks-table. This is done in order to avoid too frequent re-execution of a single task, which could prevent other tasks from executing at all. The entries will be
		 * read by the CBHTLProcessor while deciding whether a Task read from a HuntingTaskList should be executed or skipped. The idea is to skip the execution of all Tasks that have recently been executed from the current PublicIP.
		 * 
		 * @param taskID The ID of the HuntingTask that has successfully been executed
		 * @param publicIP The publicIP from which it has been executed
		 * @param serverTimeOfExecution The server time of when the execution took place
		 */
		Crossbear.CBHunter.prototype.storeHuntingTaskResultLocal = function storeHuntingTaskResultLocal(taskID, publicIP, serverTimeOfExecution) {
			
			// Build the SQL-Statement that will store the fact of the successful execution ...
			var sqlStatement = "INSERT INTO performedTasks (TaskID, PublicIP, ServerTimeOfExecution) VALUES (:tid, :pip, :time)";
			var params = new Object();
			params['tid'] = taskID;
			params['pip'] = publicIP;
			params['time'] = serverTimeOfExecution;
			
			// ... and execute it.
			cbFrontend.cbdatabase.executeAsynchronous(sqlStatement, params, null);
		};

		/**
		 * This is the callback-function that will be called when the attempt to send a list of HuntingTaskReplies to the Crossbear-server either failed or succeeded. If it succeeded the function does nothing. If it fails it tries to resend the
		 * HuntingTaskReplies up to three times. The callback function that is used by for the resending is again this function.
		 * 
		 * Please note: This function is a XMLHTTPRequest-callback-function
		 */
		Crossbear.CBHunter.prototype.sendHuntingTaskResultsCallback = function sendHuntingTaskResultsCallback() {

			// Check if the sending succeeded. If it did return ;)
			if ((this.readyState == 4) && (this.status == 200)) {
				cbFrontend.displayInformation("... done :) ");
				return;
			
			// If it didn't succeed and the reason for that was a timeout (this.status == 0) then try resending the replies (up to three times)
			} else if ((this.readyState == 4) && (this.status == 0)) { 
				
				cbFrontend.displayTechnicalFailure("CBHunter:sendHuntingTaskResultsCallback: could not connect to cbServer (connection timed out)!", false);
				
				// Resend if there haven't already been three resending-attempts
				if(this.cbCallBackParams.numOfFailedAttempts<3){
					cbFrontend.displayInformation("Attempting to resend the Hunting Task replies");
					cbFrontend.cbnet.postBinaryRetrieveBinaryFromUrl("https://" + cbFrontend.cbServerName + "/reportHTResults.jsp", cbFrontend.cbServerName + ":443", Crossbear.jsArrayToUint8Array(this.cbCallBackParams.replyRawData),self.sendHuntingTaskResultsCallback,{ replyRawData: this.cbCallBackParams.replyRawData, numOfFailedAttempts : this.cbCallBackParams.numOfFailedAttempts+1});
				} else{
					// Give up if resending the results three times didn't work either.
				}
				
				return;

			// If it didn't succeed and the reason for that was not a timeout throw an exception
			} else if ((this.readyState == 4)) {
				cbFrontend.displayTechnicalFailure("CBHunter:sendHuntingTaskResultsCallback: could not connect to cbServer (HTTP-STATUS: "+this.status+":"+this.statusText+")!", true);
				return;
			}
		};
	}
	
};
