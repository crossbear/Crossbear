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