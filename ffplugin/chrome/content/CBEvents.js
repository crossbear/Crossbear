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
 * This file defines the Events for cross-process communication (GUI-thread <-> CBHunterWorkerThread).
 * 
 * Each Event has a type (i.e. the eventtype) so the event dispatchers on both sides can easily determine the type of a event.
 * 
 * @author Thomas Riedmaier
 */


/**
 * Initialize the Worker thread (i.e. set parameters and tell the Worker-Thread the paths of the native libraries)
 * 
 * @param tracerouteSamplesPerHop How many samples with the same TTL should be made during tracerouteing
 * @param tracerouteMaxHops How many hops should maximally be visited during tracerouteing
 * @param libPaths The pathes of the native libraries (Required for Tracerouteing and Certificate-downloading)
 * @param osIsWin A flag indicating whether the current system is a Windows system or not
 * @param publicIPcacheValidity The duration in seconds that a PublicIP will be considered as unchanged (after that duration the current PublicIP will be requested)
 * @param serverIPcacheValidity The duration in seconds that the Crossbear Server IP will be considered as unchanged (after that duration the current Server IP  will be requested)
 */
Crossbear.CBHunterWorkerInitEvent = function(tracerouteSamplesPerHop, tracerouteMaxHops, libPaths, osIsWin, publicIPcacheValidity,serverIPcacheValidity) {
	this.eventtype = "CBHunterWorkerInitEvent";
	this.tracerouteSamplesPerHop = tracerouteSamplesPerHop;
	this.tracerouteMaxHops = tracerouteMaxHops;
	this.libPaths = libPaths;
	this.osIsWin = osIsWin;
	this.publicIPcacheValidity = publicIPcacheValidity;
	this.serverIPcacheValidity = serverIPcacheValidity;
};

/**
 * Notify the Worker-Thread about a new HuntingTask that it should execute
 * 
 * @param taskID The ID of the HuntingTask
 * @param ipVersion The IP-version of the IP of the HuntingTask's target
 * @param alreadyKnownHashes An array of SHA256-Hashes of certificates that are already well known for that HuntingTask
 * @param targetIP The IP of the HuntingTask's target
 * @param targetPort The port of the HuntingTask's target
 * @param targetHostname The Hostname of the HuntingTask's target
 */
Crossbear.CBHunterWorkerNewTask = function (taskID, ipVersion,alreadyKnownHashes, targetIP, targetPort, targetHostname){
	this.eventtype = "CBHunterWorkerNewTask";
	this.taskID = taskID;
	this.ipVersion = ipVersion;
	this.alreadyKnownHashes = alreadyKnownHashes;
	this.targetIP = targetIP;
	this.targetPort = targetPort;
	this.targetHostname = targetHostname;
};

/**
 * Notify the Worker-Thread about a current PublicIP of the system
 * 
 * @param ipVersion The version of the PublicIP which will be sent within this event
 * @param ip One of the current PublicIPs of the system
 * @param hMac The HMAC that was sent by the Crossbear server along with this PublicIP
 * @param timeOfObservation The local time of when this PublicIP was observed
 */
Crossbear.CBHunterWorkerNewPublicIP = function (ipVersion,ip, hMac, timeOfObservation){
	this.eventtype = "CBHunterWorkerNewPublicIP";
	this.ipVersion = ipVersion;
	this.ip = ip;
	this.hMac = hMac;
	this.timeOfObservation = timeOfObservation;
};

/**
 * Request to get the current system's PublicIP of a specific version
 * 
 * @param ipVersion The IP-version to get the publicIP for
 * @param serverIP The IP of the Crossbear server that has the same IP-version as is specified by "ipVersion"
 */
Crossbear.CBHunterWorkerNewPublicIPRequest = function (ipVersion,serverIP){
	this.eventtype = "CBHunterWorkerNewPublicIPRequest";
	this.ipVersion = ipVersion;
	this.serverIP = serverIP;
};

/**
 * Notify the Worker-Thread about the Crossbear-Server's current IP(s)
 * 
 * @param IPv4 A current IPv4 address of the Crossbear server
 * @param IPv6 A current IPv6 address of the Crossbear server
 * @param timeOfObservation The local time when these IPs were observed
 */
Crossbear.CBHunterWorkerNewServerIPs = function (IPv4,IPv6, timeOfObservation){
	this.eventtype = "CBHunterWorkerNewServerIPs";
	this.IPv4 = IPv4;
	this.IPv6 = IPv6;
	this.timeOfObservation = timeOfObservation;
};

/**
 * Request to get the current IP(s) of the Crossbear server
 */
Crossbear.CBHunterWorkerNewServerIPsRequest = function (){
	this.eventtype = "CBHunterWorkerNewServerIPsRequest";
};

/**
 * Request to get the current timestamp in server-local-time
 */
Crossbear.CBHunterWorkerServerTimeRequest = function (){
	this.eventtype = "CBHunterWorkerServerTimeRequest";
};

/**
 * Notify the Worker-Thread about the current local time of the server (required in order to set the HuntingTask-timestamps in server-local-time)
 * 
 * @param currentServerTime The current timestamp in server-local-time
 */
Crossbear.CBHunterWorkerServerTimeReply = function (currentServerTime){
	this.eventtype = "CBHunterWorkerServerTimeReply";
	this.currentServerTime = currentServerTime;
};

/**
 * Request to store the fact that a HuntingTask was successfully executed in the local database
 * 
 * @param taskID The HuntingTaskID of the task that has successfully been executed
 * @param publicIP The PublicIP that was used to execute it
 * @param serverTimeOfExecution The server time during which it was executed
 */
Crossbear.CBHunterWorkerDBStoreRequest = function (taskID, publicIP, serverTimeOfExecution) {
	this.eventtype = "CBHunterWorkerDBStoreRequest";
	this.taskID = taskID;
	this.publicIP = publicIP;
	this.serverTimeOfExecution = serverTimeOfExecution;
};
/**
 * Message containing a list of HuntingTaskResults (to be send to the Crossbear server)
 * 
 * @param results An Array of byte[]s, each representing a CBMessageTaskReply
 */
Crossbear.CBHunterWorkerHuntingResults = function (results) {
	this.eventtype = "CBHunterWorkerHuntingResults";
	this.results = results;
};

/**
 * Notification that an Error occured -> To be forwarded to the cbFrontend.displayTechnicalFailure-function
 * 
 * Please note: Unfortunately cbFrontend can't be passed to the worker since that generates a "The object could not be cloned." code:"25" exception. Therefore this Event becomes necessary.
 * 
 * @param what The message that should be displayed
 * @param critical If True Crossbear will be shut down after displaying the exception
 */
Crossbear.CBHunterWorkerError = function (what, critical) {
	this.eventtype = "CBHunterWorkerError";
	this.what = what;
	this.critical = critical;
};

/**
 * Information that should be displayed by the GUI-Thread -> To be forwarded to the cbFrontend.displayInformation-function
 * 
 * Please note: Unfortunately cbFrontend can't be passed to the worker since that generates a "The object could not be cloned." code:"25" exception. Therefore this Event becomes necessary.
 * 
 * @param what The message that should be displayed
 */
Crossbear.CBHunterWorkerInformation = function (what) {
	this.eventtype = "CBHunterWorkerInformation";
	this.what = what;
};
