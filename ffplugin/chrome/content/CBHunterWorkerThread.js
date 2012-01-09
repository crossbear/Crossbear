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
 * This file implements a Worker-Thread that is independent of the GUI-Thread. Crossbear uses the GUI-Thread to perform all operations that either need to access privileged operations (e.g. database, DNS, ...) or that can be done in an asynchronous
 * way (e.g. XMLHTTPRequests). The CBHunterWorkerThread is in turn used for the Hunting-related functionality namely Certificate-Chain-downloading and Traceroute-measurement. The reason for that is that both functionalities use c-types to call native
 * libraries or programs. Those calls might block the execution for some time which would lead to a frozen GUI when called from the GUI-Thread. Without being 100% exact one could say that the CBHunterWorkerThread executes the HuntingTasks.
 * 
 * The communication between the Worker-Thread and the GUI-Thread is done by sending Events (i.e. CBEvents). These Events will either be dispatched by the onmessage-function of this file or by the CBHunter.wtcallback-function depending on who sent them.
 * 
 * The Events that are sent TO the Worker-Thread are
 * - CBHunterWorkerInitEvent -> Initialize the Worker thread (i.e. set parameters and tell the Worker-Thread the paths of the native libraries)
 * - CBHunterWorkerNewTask -> Notify the Worker-Thread about a new HuntingTask that it should execute
 * - CBHunterWorkerNewPublicIP -> Notify the Worker-Thread about a current PublicIP of the system
 * - CBHunterWorkerNewServerIPs -> Notify the Worker-Thread about the Crossbear-Server's current IP(s)
 * - CBHunterWorkerServerTimeReply -> Notify the Worker-Thread about the current local time of the server (required in order to set the HuntingTask-timestamps in server-local-time)
 *
 * The Events that are sent BY the Worker-Thread are
 * - CBHunterWorkerNewPublicIPRequest -> Request to get the current system's PublicIP
 * - CBHunterWorkerNewServerIPsRequest -> Request to get the current IP of the Crossbear server
 * - CBHunterWorkerServerTimeRequest -> Request to get the current timestamp in server-local-time
 * - CBHunterWorkerDBStoreRequest -> Request to store the fact that a HuntingTask was executed in the local database
 * - CBHunterWorkerHuntingResults -> Message containing a list of HuntingTaskResults (to be send to the Crossbear server)
 * - CBHunterWorkerError -> Notification that an Error occured
 * - CBHunterWorkerInformation -> Information that should be displayed by the GUI-Thread
 * 
 * @author Thomas Riedmaier
 */

// Import the functionality needed by this file and define the window and window.Crypto namespaces which are not defined for a worker thread (but required in order to load crypto-js)
var window = {};
importScripts('crypto-js/crypto.js', 'CBHelper.js', 'CBEvents.js', 'CBMessages.js', 'CBCertificateChainFetcher.js', 'CBTracer.js');
var Crypto = window.Crypto;
importScripts('crypto-js/sha256.js');

// The CBTracer-object that will be used to perform the Traceroutes
var cbtracer = null;

// The CBCertificateChainFetcher-object that will be used to download Certificate-chains from the servers
var cbccf = null;

// The system's current public IPs
var publicIPv4 = null;
var publicIPv6 = null;

// The HMACs for that IPs
var publicIPv4Hmac = null;
var publicIPv6Hmac = null;

// The duration in seconds that a PublicIP will be considered as unchanged (after that duration the current PublicIP will be requested)
var publicIPcacheValidity = 0;

// The Timestamps of when a PublicIP has been observed for the system
var publicIPv4OT = 0;
var publicIPv6OT = 0;

// The current IPs of the Crossbear server
var serverIPv4 = null;
var serverIPv6 = null;

// The duration in seconds that the Crossbear Server IP will be considered as unchanged (after that duration the current Server IP  will be requested)
var serverIPcacheValidity = 0;

//The Timestamps of when a IP has been observed for the Crossbear server
var serverIPv4OT = 0;
var serverIPv6OT = 0;

// A list of HuntingTasks that are still to do
var tasksToDo = [];

// A list of HuntingTaskResults (one for each successfully executed HuntingTask)
var tasksDone = [];

// A flag indicating if the CBHunterWorkerThread is currently hunting or waiting for input of some kind (a Task, a PublicIP or a ServerIP)
var currentlyHunting = false;

// Intermediate Results of the current HuntingTask: The Trace, the CertificateChain and the PublicIP from which the Task has been executed
var currentTaskTR = "";
var currentTaskChain = [];
var currentTaksPublicIP = null;


/**
 * Most Crossbear-classes require a cbFrontend-input parameter which will be used to display warnings and information. Since using the "real" CBFrontend from a worker thread is not possible a minimal CBFrontend - the CBMiniFrontend is defined. This
 * class also implements the displayTechnicalFailure and the displayInformation-functions but instead of actually displaying the information it relays them to the real cbFrontend using the CBHunterWorkerError and the CBHunterWorkerInformation events.
 * 
 */
function CBMiniFrontend() {
	
	/**
	 * Send a CBHunterWorkerError-event to the CBHunter which will relay its content to the CBFronend.displayTechnicalFailure-function
	 * @param what The Error-message to display
	 * @param critical Is The error a critical one (i.e. should Crossbear be terminated)?
	 */
	function signalFailure(what, critical) {
		var error = new CBHunterWorkerError("CBHunterWorkerThread: "+what, critical);
		postMessage(error);
	}

	/**
	 * Send a CBHunterWorkerInformation-event to the CBHunter which will relay its content to the CBFrontend.displayInformation-function
	 * @param what The information to display
	 */
	function signalInformation(what) {
		var information = new CBHunterWorkerInformation(what);
		postMessage(information);
	}

	// Define aliases for the internal functions so they can be accessed from outside the CBMiniFrontend-class
	this.displayTechnicalFailure = signalFailure;
	this.displayInformation = signalInformation;
}

// The cbFrontend that will be used to display information and warnings
var cbFrontend = new CBMiniFrontend();

/**
 * Get the oldest HuntingTask from the tasksToDo-list and check if all prerequisites are met so it can be executed. The prerequisites for that are:
 * - There is no HuntingTask that is currently executed
 * - There is a reasonably new PublicIP of the current system available
 * - There is a reasonably new IP of the Crossbear server available
 * 
 * When everything is okay the Traceroute on the HuntingTask's target is performed. Afterwards the target's certificate chain is downloaded. Finally a request to the CBHunter for the current server time is issued. As soon as an answer on that is being 
 * received the Task's execution continues within the processServerTimeReply-function.
 */
function executeFirstHuntingTaskInList() {
	try {

		// Make sure that there is at least one task on the todo-list. If not: terminate the execution of the HuntingTask list.
		if (tasksToDo.length == 0) {
			
			// If that's not true return
			currentlyHunting = false;
			return;
		}

		// Get the current system's local time
		var theTime = Math.round(new Date().getTime() / 1000);

		// Check if a reasonably new IP (of the same version of the HuntingTask's targetIP) of the Crossbear server is known
		if ((tasksToDo[0].data.ipVersion == 4 && theTime > serverIPv4OT + serverIPcacheValidity) || (tasksToDo[0].data.ipVersion == 6 && theTime > serverIPv6OT + serverIPcacheValidity)) {
			
			// If not: request a more recent server ip
			var servIPreq = new CBHunterWorkerNewServerIPsRequest();
			
			// And suspend the HuntingTask-execution
			currentlyHunting = false;
			postMessage(servIPreq);
			return;
		}

		// See if there is a reasonably new PublicIP (of the same version of the HuntingTask's targetIP) of the current system available
		if ((tasksToDo[0].data.ipVersion == 4 && theTime > publicIPv4OT + publicIPcacheValidity) || (tasksToDo[0].data.ipVersion == 6 && theTime > publicIPv6OT + publicIPcacheValidity)) {
			
			// If not: request a more recent public ip
			var pubIPreq = new CBHunterWorkerNewPublicIPRequest(tasksToDo[0].data.ipVersion, (tasksToDo[0].data.ipVersion == 4) ? serverIPv4 : serverIPv6);
			
			// And suspend the HuntingTask-execution
			currentlyHunting = false;
			postMessage(pubIPreq);
			return;
		}

		cbFrontend.displayInformation("Executing Task " + tasksToDo[0].data.taskID);

		// Store the publicIP that will be used for the HuntingTask-execution
		currentTaksPublicIP = (tasksToDo[0].data.ipVersion == 4) ? publicIPv4 : publicIPv6;

		// Try to fetch the certificate chain from server
		currentTaskChain = cbccf.getCertificateChainFromServerFB(tasksToDo[0].data.targetIP, tasksToDo[0].data.ipVersion, tasksToDo[0].data.targetPort, tasksToDo[0].data.targetHostname);
		if(currentTaskChain == null){
			
			// If it was not possible to contact the server (e.g. because of a timeout) just skip the execution of the current Task and go on with the next one
			cbFrontend.displayInformation("Could not obtain a certificate for task"+tasksToDo[0].data.taskID+". Continuing with next one!");
			continueWithNextTask();
			return;
		}
		
		// Perform the Traceroute, remove all private IPs and add the current PublicIP
		var tracerouteResult = cbtracer.traceroute(tasksToDo[0].data.targetIP, tasksToDo[0].data.ipVersion);
		currentTaskTR = cbtracer.addOwnPublicIPAndRemovePrivateIPs(currentTaksPublicIP, tracerouteResult);
		
		// Request the current server time to add it to the HuntingTaskResult and continue the execution within the processServerTimeReply-function
		postMessage(new CBHunterWorkerServerTimeRequest());

	} catch (e) {
		cbFrontend.displayTechnicalFailure("executeFirstHuntingTaskInList:  a failure occured: "+ e, true);	
	}
}

/**
 * Remove the current HuntingTask from the todo-list and go on with the next one
 */
function continueWithNextTask() {
	tasksToDo.shift();
	executeFirstHuntingTaskInList();
}

/**
 * Check if there is a currently active HuntingTask. If there is none start executing the HuntingTask-list
 */
function startHuntingIfNotAlreadyRunning() {

	if (!currentlyHunting) {
		currentlyHunting = true;
		executeFirstHuntingTaskInList();
	}
}

/**
 * Initialize the CBHunterWorkerThread
 * @param event A CBHunterWorkerInitEvent containing all the information necessary to initialize the CBHunterWorkerThread
 */
function init(event) {
	try {
		// Set the duration in seconds that the Crossbear Server IP / the current system's publicIP will be considered as unchanged
		publicIPcacheValidity = event.data.publicIPcacheValidity;
		serverIPcacheValidity = event.data.serverIPcacheValidity;

		// Create and initialize a new CBTracer
		cbtracer = new CBTracer(cbFrontend);
		cbtracer.init(event.data.libPaths, event.data.osIsWin, event.data.tracerouteSamplesPerHop, event.data.tracerouteMaxHops);

		// Create and initialize a new CBCertificateChainFetcher
		cbccf = new CBCertificateChainFetcher(cbFrontend);
		cbccf.init(event.data.libPaths, event.data.osIsWin);

	} catch (e) {
		cbFrontend.displayTechnicalFailure("init:  a failure occured: "+e, true);
	}
}

/**
 * Somebody sent a CBHunterWorkerNewPublicIP-Event containing the information either about the system's current PublicIP version 4 or version 6. Store that information for later use. In case the lack of that information blocked the execution of a
 * HuntingTask: continue its execution.
 * 
 * @param event A CBHunterWorkerNewPublicIP containing the information either about the system's current PublicIP version 4 or version 6
 */
function storeNewPublicIP(event) {
	try {
		
		// If the CBHunterWorkerNewPublicIP's IP-version is 4 then set the publicIPv4, the publicIPv4Hmac and the publicIPv4OT (for more details see the declaration of these variables)
		if (event.data.ipVersion == 4) {
			publicIPv4 = event.data.ip;
			publicIPv4Hmac = event.data.hMac;
			publicIPv4OT = event.data.timeOfObservation;

			// If the CBHunterWorkerNewPublicIP's IP-version is 6 then set the publicIPv6, the publicIPv6Hmac and the publicIPv6OT (for more details see the declaration of these variables)
		} else if (event.data.ipVersion == 6) {
			publicIPv6 = event.data.ip;
			publicIPv6Hmac = event.data.hMac;
			publicIPv6OT = event.data.timeOfObservation;

		} else {
			cbFrontend.displayTechnicalFailure("storeNewPublicIP: received unknown ipVersion: " + ipVersion, true);
		}

		// In case there is a HuntingTask that want's to be executed: do so
		startHuntingIfNotAlreadyRunning();
		
	} catch (e) {
		cbFrontend.displayTechnicalFailure("storeNewPublicIP:  a failure occured: " + e, true);
	}
}

/**
 * Somebody sent a CBHunterWorkerNewServerIPs-Event containing the information about the currently known IPs of the Crossbear server of versions 4 and 6. Store that information for later use. In case the lack of that information blocked the execution
 * of a HuntingTask: continue its execution.
 * 
 * @param event A CBHunterWorkerNewServerIPs containing the information about the currently known IPs of the Crossbear server of version 4 and version 6
 */
function storeNewServerIPs(event) {
	try {
		// Update the global variables storing the current IPs of the Crossbear server
		serverIPv4 = event.data.IPv4;
		serverIPv6 = event.data.IPv6;

		//If the IPv4 is set then update the timeOfObservation-value of the IPv4
		if (serverIPv4 != "") {
			serverIPv4OT = event.data.timeOfObservation;
			
		// If it's not set then there is currently no ipv4-connectivity. If the current HuntingTask is a v4-HuntingTask: skip its execution
		} else if (!currentlyHunting && tasksToDo.length > 0 && tasksToDo[0].data.ipVersion == 4) {
			continueWithNextTask();
		}

		//If the IPv6 is set then update the timeOfObservation-value of the IPv6
		if (serverIPv6 != "") {
			serverIPv6OT = event.data.timeOfObservation;

			// If it's not set then there is currently no ipv6-connectivity. If the current HuntingTask is a v6-HuntingTask: skip its execution
		} else if (!currentlyHunting && tasksToDo.length > 0 && tasksToDo[0].data.ipVersion == 6) {
			continueWithNextTask();
		}

		// In case there is a HuntingTask that want's to be executed: do so
		startHuntingIfNotAlreadyRunning();
		
	} catch (e) {
		cbFrontend.displayTechnicalFailure("storeNewServerIPs:  a failure occured: " + e, true);
	}
}

/**
 * Somebody sent a CBHunterWorkerNewTask-Event containing a new HuntingTask. Add it to the current Hunting-Task-to-to-list and in case it is the first one: Start executing it. In case the HuntingTask is already waiting in the Todo-list don't add
 * it again.
 * 
 * @param event A CBHunterWorkerNewTask containing a new HuntingTask.
 */
function storeNewTask(event) {

	// Check if the task to store is actually new or already in queue
	var isNew = true;
	for ( var i = 0; i < tasksToDo.length; i++) {
		
		// Go through all task's in the queue and compare their IDs with the one of the Task that's to insert
		if (tasksToDo[i].data.taskID == event.data.taskID) {
			isNew = false;
			break;
		}
	}
	
	// Only if the task is new: Add it to the todo-list
	if (isNew) {
		tasksToDo.push(event);
	}

	// In case there is a HuntingTask that want's to be executed: do so
	startHuntingIfNotAlreadyRunning();
}

/**
 * After having performed and stored the Traceroute and downloaded the certificate chain the executeFirstHuntingTaskInList-function will issue a CBHunterWorkerServerTimeRequest. The answer to that request will be passed to this function. Therefore this function has access to
 * - A Traceroute for the current HuntingTask
 * - A certificate chain for the current HuntingTask
 * - The current server time.
 * 
 * This is enough to generate a HuntingTaskResult which will be done within this function. After that the fact of the successful execution of the HuntingTask will be stored in the local database. Finally the HuntingTaskResult will be stored in the "tasksDone"-List and - in
 * case that list has grown to a length of five or in case there are no more Tasks - wil be sent to the CBHunter. The CBHunter will in turn send it to the Crossbear Server.
 * 
 * @param event A CBHunterWorkerServerTimeReply containing the estimated current local time of the Crossbear Server
 */
function processServerTimeReply(event) {
	try {

		// Calculate the SHA256-Hash of the target's certificate
		var serverCertHash = (currentTaskChain.length > 0) ? Crypto.SHA256(currentTaskChain[0], {
			asBytes : true
		}) : [];

		// Store the fact of the successful execution of the HuntingTask in the local database
		var dbStoreReq = new CBHunterWorkerDBStoreRequest(tasksToDo[0].data.taskID, currentTaksPublicIP, event.data.currentServerTime);
		postMessage(dbStoreReq);

		/*
		 * Build a HuntingTaskReply
		 */ 
		
		// First: Check if the certificate that has been observed is already well known to the server (i.e. if its hash is within the alreadyKnownHashes-list)
		var alreadyKnown = false;
		for ( var i = 0; i < tasksToDo[0].data.alreadyKnownHashes.length; i++) {
			if (arrayCompare(tasksToDo[0].data.alreadyKnownHashes[i], serverCertHash)) {
				alreadyKnown = true;
				break;
			}
		}

		// Second: Fetch the HMAC of the used PublicIP to prove that the claimed start of the Traceroute is correct
		var hMac = (tasksToDo[0].data.ipVersion == 4) ? publicIPv4Hmac : publicIPv6Hmac;

		// Third: Build the actual HuntingTaskReply depending on whether the observed certificate is already well known to the server
		var taskReply = null;
		if (alreadyKnown) {
			taskReply = new CBMessageTaskReplyKnownCert(tasksToDo[0].data.taskID, event.data.currentServerTime, hMac, serverCertHash, currentTaskTR);
		} else {
			taskReply = new CBMessageTaskReplyNewCert(tasksToDo[0].data.taskID, event.data.currentServerTime, hMac, currentTaskChain, currentTaskTR);
		}
		
		// Fourth: Add the HuntingTaskReply to the tasksDone-list
		tasksDone.push(taskReply.getBytes());

		// Send the HuntingTask-results to the server in case that enough data has accumulated or no more task have to be done
		if (tasksDone.length >= 5 || tasksToDo.length == 1) {
			
			// Sending the Results to the server means sending them to the CBHunter via a CBHunterWorkerHuntingResults-Event. The CBHunter will then send the results to the Crossbear server.
			var huntingResults = new CBHunterWorkerHuntingResults(tasksDone);
			postMessage(huntingResults);
			tasksDone = [];
		}

		// Continue with the execution of the next task (if there is any)
		continueWithNextTask();

	} catch (e) {
		cbFrontend.displayTechnicalFailure("processServerTimeReply:  a failure occured: " + e, true);
	}
}
/**
 * The worker-thread's Event-Dispatcher. The Events that are expected are defined at the very beginning of this file. All others will generate a critical failure.
 * 
 * @param event A nsIWorkerMessageEvent that is sent to the CBHunterWorkerThread using the postMessage() function. The event.data field is expected to be a Event defined within the CBEvents-file.
 */
onmessage = function(event) {

	try {

		// Look on the eventtype of the Event an perform actions according to it
		if (event.data.eventtype) {
			if (event.data.eventtype == "CBHunterWorkerInitEvent") {
				init(event);
				return;

			} else if (event.data.eventtype == "CBHunterWorkerNewPublicIP") {
				storeNewPublicIP(event);
				return;

			} else if (event.data.eventtype == "CBHunterWorkerNewServerIPs") {
				storeNewServerIPs(event);
				return;

			} else if (event.data.eventtype == "CBHunterWorkerNewTask") {
				storeNewTask(event);
				return;

			} else if (event.data.eventtype == "CBHunterWorkerServerTimeReply") {
				processServerTimeReply(event);
				return;

			}
		}
		cbFrontend.displayTechnicalFailure("dispatcher: received unknown event: " + event.data, true);

	} catch (e) {
		cbFrontend.displayTechnicalFailure("dispatcher: a failure occured: " + e, true);
	}

};