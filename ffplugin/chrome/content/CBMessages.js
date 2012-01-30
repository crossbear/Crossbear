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
 * This file defines all messages that are sent between the Crossbear server and client as well as the functionality related to parsing them.
 * 
 * @author Thomas Riedmaier
 */

/**
 * A PublicIPNotification is sent to the client every time it want's to know its PublicIP. The client needs this IP since it will add it as first element to the traces made during Hunting. The trace
 * must contain this IP since this is the IP of the Mitm in the scenario of an poisoned public access point (and others). The server doesn't necessarily observe this IP when the client sends the
 * HuntingTaskReply since it might send it over IPv6 while it hunted using IPv4. Therefore the PublicIP needs to be sent to the client. Moreover it needs to be sent in a way that can't be forged by a
 * malicious client. That's way each PublicIPNotification-message contains a HMAC guaranteeing the authenticity of the PublicIP. Since only the server knows the Key of the HMAC only the server is able
 * to generate it and to use it for authenticity checks.
 * 
 * The structure of the PublicIPNotification-message is
 * - Header
 * - The HMAC for the client's PublicIP address (32 bytes)
 * - The client's PublicIP address (4 or 16 bytes)
 * 
 * Please Note: There are actually two different PublicIPNotification-messages: MESSAGE_TYPE_PUBLIC_IP_NOTIF4 and MESSAGE_TYPE_PUBLIC_IP_NOTIF6. The reason for this is that the decoding becomes more easy when
 * the version of the IP-Address is known as soon as the message's header is read.
 * 
 * @param rawData The bytes of a PublicIPNotification-message (without the header) that will be converted into a CBMessagePublicIPNotif-object
 * @param ipVersion The IP-Version of the IP that was observed by the server
 * 
 * @author Thomas Riedmaier
 */
function CBMessagePublicIPNotif(rawData, ipVersion) {
	
	// Remember the the ipVersion
	this.ipVersion = ipVersion;

	// Extract the HMAC (first 32 bytes of the message)
	this.hMac = uint8ArrayToJSArray(rawData.subarray(0, 32));
	
	// Extract the PublicIP (remainder of the message)
	this.publicIP = byteArrayIpToString(rawData.subarray(32));

	// Initialize the member function references for the class prototype (like this it's only done once and not every time a instance of this object is created)
	if (typeof (_cbmessagepublicipnotif_prototype_called) == 'undefined') {
		__cbmessagepublicipnotif_prototype_called = true;

		/**
		 * Getter-function for the message's IP-Version
		 */
		CBMessagePublicIPNotif.prototype.getIPVersion = function getIPVersion() {
			return this.ipVersion;
		};

		/**
		 * Getter-function for the message's HMAC-field
		 */
		CBMessagePublicIPNotif.prototype.getHMac = function getHMac() {
			return this.hMac;
		};

		/**
		 * Getter-function for the message's Public-IP-field
		 */
		CBMessagePublicIPNotif.prototype.getPublicIP = function getPublicIP() {
			return this.publicIP;
		};
	}

}

/**
 * The CurrentServerTime-message is sent to the client every time a hunting task is sent to it. The message contains a Timestamp of the current server time and is used to give the client the ability
 * to sent Hunting Task Replies with a Timestamp that is at least roughly equal to the Timestamp the server would have recorded if it would have executed the Hunting Task at that time.
 * 
 * The structure of the CurrentServerTime-message is
 * - Header
 * - Timestamp of current server time (4 bytes)
 * 
 * @param rawData The bytes of a CurrentServerTime-message (without the header) that will be converted into a CBMessageCurrentServerTime-object
 * 
 * @author Thomas Riedmaier
 */
function CBMessageCurrentServerTime(rawData) {
	
	// Extract the timestamp representing the current server time from the message
	this.currentServerTime = bytesToInt(rawData.subarray(0));

	// Initialize the member function references for the class prototype (like this it's only done once and not every time a instance of this object is created)
	if (typeof (_cbmessagecurrentservertime_prototype_called) == 'undefined') {
		_cbmessagecurrentservertime_prototype_called = true;

		/**
		 * Getter-function for the message's Current-Server-Time-field
		 */
		CBMessageCurrentServerTime.prototype.getCurrentServerTime = function getCurrentServerTime() {
			return this.currentServerTime;
		};

	}
}

/**
 * HuntingTask-messages are sent from the Crossbear server to the Crossbear client(s). Upon receiving a HuntingTask-message a client will contact the scan-target and download its certificate chain.
 * Also it will run a traceroute on the scan-target. After that it will check if the certificate it received is already well known to the server. Depending on the result of this check the client will
 * either generate a HuntingTaskReplyKnownCertChain-message or a HuntingTaskReplyNewCertChain-message and send it to the server.
 * 
 * The structure of the HuntingTask-message is
 * - Header
 * - TaskID (four bytes) 
 * - Number of certificates that are already well known 
 * - Array of SHA256-hashes of the certificates that are already well known 
 * - IP Address of the scan-target in binary format (4 or 16 bytes)
 * - Port of the scan-target (two bytes) 
 * - Hostname of the scan-target (String of variable length)
 * 
 * Please Note: There are actually two different HuntingTask-messages: MESSAGE_TYPE_IPV6_SHA256_TASK and MESSAGE_TYPE_IPV4_SHA256_TASK. The reason for this is that the decoding becomes more easy when
 * the version of the IP-Address is known as soon as the message's header is read.
 * 
 * @param rawData The bytes of a HuntingTask-message (without the header) that will be converted into a CBMessageHuntingTask-object
 * @param ipVersion The IP-Version of the target of the hunting task
 * 
 * @author Thomas Riedmaier
 */
function CBMessageHuntingTask(rawData, ipVersion) {
	
	// Remember the the ipVersion and calculate how many Bytes an IP of that version consumes when stored
	this.ipVersion = ipVersion;
	this.ipBytes = (this.ipVersion == 4) ? 4 : 16;

	// Extract the taskID and the number of already well known certificates. These are the only two fields that are extracted on initialization. The remaining parameters will be extracted on demand.
	this.taskID = bytesToInt(rawData.subarray(0, 4));
	this.numberOfAlreadyKnownHashes = rawData[4];
	
	// In order to be able to extract the other fields on demand store the rawData ...
	this.rawData = rawData;

	// ... and set all remaining fields to null
	this.targetIP = null;
	this.targetPort = null;
	this.hostName = null;
	this.AlreadyKnownHashes = null;

	// Initialize the member function references for the class prototype (like this it's only done once and not every time a instance of this object is created)
	if (typeof (_cbmessagehuntingtask_prototype_called) == 'undefined') {
		_cbmessagehuntingtask_prototype_called = true;

		/**
		 * Getter-function for the message's TaskID-field
		 */
		CBMessageHuntingTask.prototype.getTaskID = function getTaskID() {
			return this.taskID;
		};

		/**
		 * Getter-function for the message's IP-Version
		 */
		CBMessageHuntingTask.prototype.getIPVersion = function getIPVersion() {
			return this.ipVersion;
		};

		/**
		 * Getter-function for the task's already well known hashes (will return an array of byte[]s)
		 */
		CBMessageHuntingTask.prototype.getAlreadyKnownHashes = function getAlreadyKnownHashes() {
			
			// If the hashes have not yet been extracted from the message's raw data: do so
			if (this.AlreadyKnownHashes == null) {

				// Read the message's Already-Known-Hashes fields in chunks of size 32 (= size of a SHA256-hash) and store them
				this.AlreadyKnownHashes = [];
				for ( var i = 0; i < this.numberOfAlreadyKnownHashes; i++) {
					this.AlreadyKnownHashes.push(uint8ArrayToJSArray(this.rawData.subarray(5 + i * 32, 5 + (i + 1) * 32)));
				}
			}

			// Return the task's already well known hashes as an array of byte[]s
			return this.AlreadyKnownHashes;
		};

		/**
		 * Getter-function for the IP of the target of the hunting task (will return a String)
		 */
		CBMessageHuntingTask.prototype.getTargetIP = function getTargetIP() {
			
			// If the IP has not yet been extracted from the message's raw data: do so
			if (this.targetIP == null) {

				// Read the Target-IP-field of the message and convert it into a string
				this.targetIP = byteArrayIpToString(this.rawData.subarray(5 + this.numberOfAlreadyKnownHashes * 32, 5 + this.ipBytes + this.numberOfAlreadyKnownHashes * 32));
			}

			// Return the String-representation of the IP
			return this.targetIP;
		};

		/**
		 * Getter-function for the Port of the target of the hunting task
		 */
		CBMessageHuntingTask.prototype.getTargetPort = function getTargetPort() {
			
			// If the Port has not yet been extracted from the message's raw data: do so
			if (this.targetPort == null) {

				// Read the Target-Port-field of the message and convert it into a number
				this.targetPort = bytesToShort(this.rawData.subarray(5 + this.ipBytes + this.numberOfAlreadyKnownHashes * 32, 7 + this.ipBytes + this.numberOfAlreadyKnownHashes * 32));
			}

			// Return the port as a number
			return this.targetPort;
		};

		/**
		 * Getter-function for the Hostname of the target of the hunting task
		 */
		CBMessageHuntingTask.prototype.getHostname = function getHostname() {
			
			// If the Hostname has not yet been extracted from the message's raw data: do so
			if (this.hostName == null) {

				// Read the Target-Hostname-field
				this.hostName = Crypto.charenc.Binary.bytesToString(this.rawData.subarray(7 + this.ipBytes + this.numberOfAlreadyKnownHashes * 32));
			}

			// Return the Hostname as a string
			return this.hostName;
		};
	}
}

/** 
 * A CertVerifyResult-message is sent in response to a CertVerifyRequest. It contains several CertJudgments which will be combined into a Report-String and a Rating which sums up the report in a single number.
 * 
 * The structure of the CertVerifyResult-message is
 * - Header
 * - Rating (one byte)
 * - Report about the certificate (String of variable length)
 * 
 * @param rawData The bytes of a CertVerifyResult-message (without the header) that will be converted into a CBMessageCertVerifyResult-object
 * 
 * @author Thomas Riedmaier
 */

function CBMessageCertVerifyResult(rawData) {

	// The message data will be extracted on demand. In order to be able to extract the fields on demand store the rawData ...
	this.rawData = rawData;

	// ... and set all fields to null
	this.judgments = null;
	this.rating = null;

	// Initialize the member function references for the class prototype (like this it's only done once and not every time a instance of this object is created)
	if (typeof (_cbmessagecertverifyresult_prototype_called) == 'undefined') {
		_cbmessagecertverifyresult_prototype_called = true;

		/**
		 * Getter-function for the message's Rating-field
		 */
		CBMessageCertVerifyResult.prototype.getRating = function getRating() {
			
			// If the Rating has not yet been extracted from the message's raw data: do so
			if (this.rating == null) {

				this.rating = this.rawData[0];
			}

			// Return the rating as a number
			return this.rating;
		};

		/**
		 * Getter-function for the message's Judgment-field
		 */
		CBMessageCertVerifyResult.prototype.getJudgments = function getJudgments() {
			
			// If the Judgments have not yet been extracted from the message's raw data: do so
			if (this.judgments == null) {

				this.judgments = Crypto.charenc.Binary.bytesToString(this.rawData.subarray(1));
			}

			// Return the Judgments as a String
			return this.judgments;
		};
	}
}

/**
 * A CertVerifyRequest-message is issued by the client to request the verification of a certificate that it obtained from a server. 
 * 
 * The structure of the CertVerifyRequest-message is
 * - Header
 * - Certificate (DER-encoding)
 * - Server that sent the certificate in the format HostName|HostIP|HostPort
 * 
 * Calling this function/constructor will generate a CertVerifyRequest-message
 * 
 * @param certChain The certificate chain observed by the client (DER-encoding)
 * @param host A String specifying the Host from which the certificate was observed (format: HostName|HostIP|HostPort)
 * @param options The options that were chosen by the user (one byte). Currently only the lsb has a meaning: User is behind a ssl-proxy (yes:1; no:0)
 * 
 * @author Thomas Riedmaier
 */
function CBMessageCertVerifyRequest(certChain, host, options) {
	this.certChain = certChain;
	this.host = host;
	this.options = options;

	// Initialize the member function references for the class prototype (like this it's only done once and not every time a instance of this object is created)
	if (typeof (_cbmessagecertverifyrequest_prototype_called) == 'undefined') {
		_cbmessagecertverifyrequest_prototype_called = true;

		/**
		 * Get the message's bytes 
		 * @returns The byte[]-representation of the CertVerifyRequest-message
		 */
		CBMessageCertVerifyRequest.prototype.getBytes = function getBytes() {

			// First part of the data: The options, that the user chose
			var messageData = [this.options & 255];
	
			// Second part: the number of how many certificates are part of the chain
			messageData = messageData.concat(this.certChain.length & 255);

			// Third part: the certificate chain (beginning with the server certificate)
			for ( var i = 0; i < Math.min(this.certChain.length, 255); i++) {
				messageData = messageData.concat(this.certChain[i]);
			}

			// Fourth part: the host from which it was received (required for the server to query the host for the certificate).
			messageData = messageData.concat(Crypto.charenc.Binary.stringToBytes(this.host));

			// Add the Header (message-type and message-length) to make it a valid CERT_VERIFY_REQUEST message
			return [ CBMessageTypes.CERT_VERIFY_REQUEST ].concat(shortToBytes(messageData.length + 3)).concat(messageData);

		};
	}
}

/**
 * A PublicIPNotifRequest is a message that is meant to be sent to the getPublicIP.jsp. It contains a AES256 key encrypted with the server's public RSA key. The AES- key is required to safely send the
 * PublicIPNotification-message to the client over a non-ssl connection.
 * 
 * Calling this function/constructor will generate a PublicIPNotification-message
 * 
 * @param rsaEncAESKey The AES256-key to send to the server.
 * 
 * @author Thomas Riedmaier
 */
function CBMessagePublicIPNotifRequest(rsaEncAESKey) {
	this.rsaEncAESKey = rsaEncAESKey;

	// Initialize the member function references for the class prototype (like this it's only done once and not every time a instance of this object is created)
	if (typeof (_cbmessagepublicipnotifrequest_prototype_called) == 'undefined') {
		_cbmessagepublicipnotifrequest_prototype_called = true;

		/**
		 * Get the message's bytes 
		 * @returns The byte[]-representation of the PublicIPNotifRequest-message
		 */
		CBMessagePublicIPNotifRequest.prototype.getBytes = function getBytes() {

			// Message content consists of the rsaEncAESKey only
			var messageData = this.rsaEncAESKey;

			// Add the Header (message-type and message-length) to make it a valid PUBLIC_IP_NOTIFICATION_REQUEST message
			return [ CBMessageTypes.PUBLIC_IP_NOTIFICATION_REQUEST ].concat(shortToBytes(messageData.length + 3)).concat(messageData);

		};
	}
}

/**
 * A HuntingTaskReplyNewCertChain-message is one of the two possible messages that could be sent in reply to a HuntingTask. It will be sent in case that the client observed a certificate that is NOT YET
 * well known by the server.
 * 
 * 
 * The structure of the HuntingTaskReplyNewCertChain-message is
 * - Header
 * - Task ID (4 bytes)
 * - Server time of execution (4 bytes)
 * - HMAC of the PublicIP that was inserted in the trace to the server as first hop(32 bytes)
 * - The length of the certificate chain that was observed by the client (1 byte)
 * - The certificate chain observed by the client (byte[] of variable length)
 * - Trace to the target (String of variable length)
 * 
 * Calling this function/constructor will generate a CBMessageTaskReplyNewCertChain-message
 * 
 * @param taskID The HuntingTask's ID for which this reply is sent
 * @param serverTimeOfExecution The estimated server local time when the hunting task was executed
 * @param hMac The HMAC of the PublicIP that was inserted in the trace to the server as first hop
 * @param certChain The certificate chain observed by the client
 * @param trace The trace to the target
 * 
 * @author Thomas Riedmaier
 */
function CBMessageTaskReplyNewCertChain(taskID, serverTimeOfExecution, hMac, certChain, trace) {
	this.taskID = taskID;
	this.serverTimeOfExecution = serverTimeOfExecution;
	this.hMac = hMac;
	this.certChain = certChain;
	this.trace = trace;

	// Initialize the member function references for the class prototype (like this it's only done once and not every time a instance of this object is created)
	if (typeof (_cbmessagetaskreplynewcertchain_prototype_called) == 'undefined') {
		_cbmessagetaskreplynewcertchain_prototype_called = true;

		/**
		 * Get the message's bytes 
		 * @returns The byte[]-representation of the HuntingTaskReplyNewCertChain-message
		 */
		CBMessageTaskReplyNewCertChain.prototype.getBytes = function getBytes() {

			// First part of the data: the task id
			var messageData = intToBytes(this.taskID);

			// Second part: the server time when the task was executed
			messageData = messageData.concat(intToBytes(this.serverTimeOfExecution));

			// Third part: the HMAC of the public IP used for the traceroute (needed by the server to validate the result)
			messageData = messageData.concat(this.hMac);

			// Fourth part: the number of how many certificates are part of the chain
			messageData = messageData.concat(this.certChain.length & 255);

			// Fifth part: the certificate chain (beginning with the server certificate)
			for ( var i = 0; i < Math.min(this.certChain.length, 255); i++) {
				messageData = messageData.concat(this.certChain[i]);
			}

			// Sixth part: the trace to the server
			messageData = messageData.concat(Crypto.charenc.Binary.stringToBytes(this.trace));

			// Add the Header (message-type and message-length) to make it a valid TASK_REPLY_NEW_CERT message
			return [ CBMessageTypes.TASK_REPLY_NEW_CERT ].concat(shortToBytes(messageData.length + 3)).concat(messageData);

		};
	}
}

/**
 * A HuntingTaskReplyKnownCertChain-message is one of the two possible messages that could be sent in reply to a HuntingTask. It will be sent in case that the client observed a certificate that is already
 * well known by the server.
 * 
 * The structure of the HuntingTaskReplyKnownCertChain-message is
 * - Header
 * - Task ID (4 bytes)
 * - Server time of execution (4 bytes)
 * - HMAC of the PublicIP that was inserted in the trace to the server as first hop(32 bytes)
 * - Hash of the observed certificate (32 bytes)
 * - Trace to the server (String of variable length)
 * 
 * Calling this function/constructor will generate a CBMessageTaskReplyNewCertChain-message
 * 
 * @param taskID The HuntingTask's ID for which this reply is sent
 * @param serverTimeOfExecution The estimated server local time when the hunting task was executed
 * @param hMac The HMAC of the PublicIP that was inserted in the trace to the server as first hop
 * @param serverCertHash The SHA256-Hash of the observed certificate
 * @param trace The trace to the target
 * 
 * @author Thomas Riedmaier
 */
function CBMessageTaskReplyKnownCertChain(taskID, serverTimeOfExecution, hMac, serverCertHash, trace) {
	this.taskID = taskID;
	this.serverTimeOfExecution = serverTimeOfExecution;
	this.hMac = hMac;
	this.serverCertHash = serverCertHash;
	this.trace = trace;

	// Initialize the member function references for the class prototype (like this it's only done once and not every time a instance of this object is created)
	if (typeof (_cbmessagetaskreplyknowncertchain_prototype_called) == 'undefined') {
		_cbmessagetaskreplyknowncertchain_prototype_called = true;

		/**
		 * Get the message's bytes 
		 * @returns The byte[]-representation of the HuntingTaskReplyKnownCertChain-message
		 */
		CBMessageTaskReplyKnownCertChain.prototype.getBytes = function getBytes() {

			// First part of the data: the task id
			var messageData = intToBytes(this.taskID);

			// Second part: the server time when the task was executed
			messageData = messageData.concat(intToBytes(this.serverTimeOfExecution));

			// Third part: the HMAC of the public IP used for the traceroute (needed by the server to validate the result)
			messageData = messageData.concat(this.hMac);

			// Fourth part: the hash of the observed certificate
			messageData = messageData.concat(this.serverCertHash);

			// Fifth part: the trace to the server
			messageData = messageData.concat(Crypto.charenc.Binary.stringToBytes(this.trace));

			// Add the Header (message-type and message-length) to make it a valid TASK_REPLY_KNOWN_CERT message
			return [ CBMessageTypes.TASK_REPLY_KNOWN_CERT ].concat(shortToBytes(messageData.length + 3)).concat(messageData);

		};
	}
}

/**
 * The communication between the Crossbear server and its clients is entirely performed by sending messages. Each message has a one-byte "Type"-field.
 * 
 * The currently implemented Messages use the following Message-Type-Identifiers:
 */
var CBMessageTypes = {
	// Messages used to tell a Crossbear-client which public IP it is using.
	PUBLIC_IP_NOTIF4 : 0,
	PUBLIC_IP_NOTIF6 : 1,

	// Message to request the server to tell the client which public IP it is using
	PUBLIC_IP_NOTIFICATION_REQUEST : 2,

	// Message telling which is the current local time at the server (to loosely synchronize clocks)
	CURRENT_SERVER_TIME : 5,

	// Messages representing HuntingTasks
	IPV4_SHA256_TASK : 10,
	IPV6_SHA256_TASK : 11,

	// Messages representing replies for HuntingTasks
	TASK_REPLY_NEW_CERT : 20,
	TASK_REPLY_KNOWN_CERT : 21,

	// Messages to request a certificate verification and to receive it's result
	CERT_VERIFY_REQUEST : 100,
	CERT_VERIFY_RESULT : 110,
};

/**
 * This function takes as input a byte[] representing an array of messages sent by the Crossbear-server. It decodes these messages and returns an array of CBMessages.
 * 
 * @param uint8Raw The byte[]-representation of an array of Messages
 * @param cbFrontend The cbFrontend-class that will be used to display information/errors
 * @returns An array of CBMessages which are the Javascript-representations of the Messages passed by the uint8Raw parameter
 * 
 * @author Thomas Riedmaier
 */
function messageBuilder(uint8Raw, cbFrontend) {

	var decodedMessages = [];

	// Go through the array and read all of the contained messages. Therefore set the read pointer to the beginning og the message-array.
	var currentReadPos = 0;
	while (true) {
		
		// For each message extract the length field ...
		var currentMessageLength = bytesToShort([ uint8Raw[currentReadPos + 1], uint8Raw[currentReadPos + 2] ]);

		// ... and copy it's data to a new array (according to that length field)
		var messageData = uint8Raw.subarray(currentReadPos + 3, currentReadPos + currentMessageLength);

		// In case a invalid message was received the length-field might not be correct (i.e. the raw-data was not as long as the message-length-field claimed) -> catch this here
		if (messageData.length + 3 != currentMessageLength) {
			cbFrontend.displayTechnicalFailure("messageBuilder: tried to decode a message with invalid length parameter: " + messageData.length + " vs " + currentMessageLength, true);
		}

		// Read the message's type ...
		var typ = uint8Raw[currentReadPos];

		// ... and build a CBMessage-object depending on that type
		if (typ == CBMessageTypes.PUBLIC_IP_NOTIF4) {
			decodedMessages.push(new CBMessagePublicIPNotif(messageData, 4));

		} else if (typ == CBMessageTypes.PUBLIC_IP_NOTIF6) {
			decodedMessages.push(new CBMessagePublicIPNotif(messageData, 6));

		} else if (typ == CBMessageTypes.CURRENT_SERVER_TIME) {
			decodedMessages.push(new CBMessageCurrentServerTime(messageData));

		} else if (typ == CBMessageTypes.IPV4_SHA256_TASK) {
			decodedMessages.push(new CBMessageHuntingTask(messageData, 4));

		} else if (typ == CBMessageTypes.IPV6_SHA256_TASK) {
			decodedMessages.push(new CBMessageHuntingTask(messageData, 6));

		} else if (typ == CBMessageTypes.CERT_VERIFY_RESULT) {
			decodedMessages.push(new CBMessageCertVerifyResult(messageData));
			
		// If an unknown type has been observed: Throw an exception 
		} else {
			cbFrontend.displayTechnicalFailure("messageBuilder: received unknown message type: " + type, true);
		}

		// Set the read-pointer to the beginning of the next message
		currentReadPos += currentMessageLength;

		// If the whole input is read without any error: return
		if (currentReadPos == uint8Raw.length) {
			break;
		}
	}

	// Finally return the decoded messages
	return decodedMessages;
}