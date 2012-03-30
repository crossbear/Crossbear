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
 * The CBTracer class provides a Traceroute-like functionality for Crossbear. Since Javascript doesn't provide neither low-level network access nor comfortable piping of external processes, CBTracer uses c-types to do so.
 * 
 * The main restriction imposed upon this class is the fact that creating RAW-Sockets requires admin/root privileges. The current workarounds implemented by Crossbear are: 
 * - Windows: Use the "ping"-functionality provided by the IPHLPAPI.dll to simulate Traceroutes. Since c-types doesn't allow calling "GetLastError" from Javascript (BUG-ID 684017), the IPHLPAPI-calls are performed inside the crossbear.dll 
 * - Unix/Linux: Execute the system's "ping" and "ping6" commands, read their output and use it to simulate Traceroutes.
 * 
 * @param cbFrontend The cbFrontend-class that will be used to display information/errors
 * 
 * @author Thomas Riedmaier
 */
Crossbear.CBTracer = function (cbFrontend) {
	this.cbFrontend = cbFrontend;
	
	// Flag indicating if Crossbear is currently executed on a Windows OS
	this.osIsWin = false;
	
	// Container for opened libraries
	this.libs = null;
	
	// Container for defined c-types
	this.types = null;
	
	// Container for defined c-type-functions
	this.functions = null;
	
	// Parameters for the traceroute: How many samples should be taken per hop (i.e. should be sent with the same TTL) and how many hops should be taken into account before terminating the Traceroute?
	this.samplesPerHop = -1;
	this.MaxHops = -1;

	// "this" does not always point to THIS object (especially in callback functions). Therefore I use the "self" variable to hold a handle on THIS object
	var self = this;

	// Initialize the member function references for the class prototype (like this it's only done once and not every time a instance of this object is created)
	if (typeof (_crossbear_tracer_prototype_called) == 'undefined') {
		_crossbear_tracer_prototype_called = true;
		
		/**
		 * Open the native libraries required to perform the Traceroute (lib-c on unix/linux and crossbear.dll on windows)
		 * 
		 * @param libs The container that will hold the references to the libraries once they are opened
		 * @param libPaths The container that holds the paths of the native libraries
		 */
		Crossbear.CBTracer.prototype.openNativeLibraries = function openNativeLibraries(libs, libPaths) {

			// Load crossbear.dll on windows 
			if (self.osIsWin) {
				
				try {
					libs.crossbearLib = ctypes.open(libPaths.crossbearLib);
				} catch (e) {
					cbFrontend.displayTechnicalFailure("CBTracer: Failed to open crossbear-library: " + libPaths.crossbearLib, true);
					return false;
				}
			
			// Load lib-c on linux/unix
			} else {

				try {
					libs.cLib = ctypes.open(libPaths.cLib);
				} catch (e) {
					cbFrontend.displayTechnicalFailure("CBTracer: Failed to open c-library: " + libPaths.cLib, true);
					return false;
				}
			}

			return true;
		};
		
		/**
		 * Define the c-types used by the function-calls to the native libraries
		 * 
		 * @param types The container that will hold these c-type definitions
		 */
		Crossbear.CBTracer.prototype.defineNativeLibTypes = function defineNativeLibTypes(types) {

			// Defining all of the used structs inflates the source code a lot and is not necessary. Therefore I only define the structs that are actually necessary. All others will be represented by "someStruct" which is a generic struct.
			types.someStruct = ctypes.StructType("someStruct");
			
			if(self.osIsWin){
				
				//None needed
				
			} else {
				
				// OS specific C-Constants
				types.PR_AF_INET = 2;
				types.PR_AF_INET6 = 10;
			}
			
		};
		
		/**
		 * Define the c-type-functions used within the CBTracer class
		 * 
		 * @param functions The container that will hold these c-type definitions
		 * @param types The container that contains the c-type-definitions
		 * @param libs The container that contains references to the native libraries
		 */
		Crossbear.CBTracer.prototype.defineNativelibFunctions = function defineNativelibFunctions(functions, types, libs) {
			
			
			if(self.osIsWin){

				// See crossbear.cpp
				functions.ping = libs.crossbearLib.declare("ping", 
						ctypes.default_abi, 
						ctypes.bool, 
						ctypes.jschar.ptr, 
						ctypes.int32_t, 
						ctypes.jschar.ptr, 
						ctypes.int32_t);
				
			} else{

				// See http://linux.die.net/man/3/malloc
				functions.malloc = libs.cLib.declare("malloc", 
					ctypes.default_abi, 
					ctypes.voidptr_t, 
					ctypes.uint32_t);
			
				// See http://linux.die.net/man/3/free
				functions.free = libs.cLib.declare("free", 
					ctypes.default_abi, 
					ctypes.void_t, 
					ctypes.voidptr_t);
				
				// See http://linux.die.net/man/3/popen
				functions.popen = libs.cLib.declare("popen", 
						ctypes.default_abi, 
						types.someStruct.ptr, 
						ctypes.char.ptr, 
						ctypes.char.ptr);
				
				// See http://linux.die.net/man/3/pclose
				functions.pclose = libs.cLib.declare("pclose", 
						ctypes.default_abi, 
						ctypes.int, 
						types.someStruct.ptr);

				// See http://linux.die.net/man/3/fgetc
				functions.fgetc = libs.cLib.declare("fgetc", 
						ctypes.default_abi, 
						ctypes.int, 
						types.someStruct.ptr);

				// See http://linux.die.net/man/3/inet_pton
				functions.inet_pton = libs.cLib.declare("inet_pton", 
						ctypes.default_abi, 
						ctypes.int, 
						ctypes.int, 
						ctypes.char.ptr, 
						ctypes.voidptr_t);

			}
		};

		/**
		 * Do the necessary initializations so CBTracer can be used to generate Traceroutes
		 * 
		 * @param libPaths The container that holds the paths of the native libraries
		 * @param osIsWin Flag indicating if Crossbear is currently executed on a Windows OS
		 * @param samplesPerHop How many samples should be taken per hop (i.e. should be sent with the same TTL) during a Traceroute?
		 * @param MaxHops How many hops should be taken into account before terminating a Traceroute?
		 */
		Crossbear.CBTracer.prototype.init = function init(libPaths, osIsWin, samplesPerHop, MaxHops) {
			try {
				
				// Store the parameters that will be used to perform the Traceroutes
				self.samplesPerHop = samplesPerHop;
				self.MaxHops = MaxHops;
				
				// Initialize the native libraries depending on the current OS:
				self.osIsWin = osIsWin;

				// First define the handles to the libraries themselves
				self.libs = new Object();
				self.openNativeLibraries(self.libs,libPaths);

				// Then define the c-types
				self.types = new Object();
				self.defineNativeLibTypes(self.types);

				// Finally define the c-type-functions
				self.functions = new Object();
				self.defineNativelibFunctions(self.functions, self.types, self.libs);

			} catch (e) {
				cbFrontend.displayTechnicalFailure("CBTracer:init failed: " + e, true);
			}
		};
		
		
		/**
		 * Scan the textual output of a "ping" or "ping6" command for IPs that don't match a reference IP.
		 * 
		 * @param pingOutput The textual output of a "ping" or "ping6" command to scan
		 * @param referenceIP The IP to compare all found IPs with
		 * @returns Null if no non-matching IP is found or the first non-matching IP
		 */
		Crossbear.CBTracer.prototype.getFirstNonMatchIP = function getFirstNonMatchIP(pingOutput, referenceIP) {
			
			// Allocate a buffer that can be used by c-types-functions
			var addressBuf = self.functions.malloc(128);
			if(addressBuf == 0){
				cbFrontend.displayTechnicalFailure("CBTracer:getFirstNonMatchIP: malloc failed.",true);
				return null;
			}

			// Define a Regex that will match all IPs (and more)
			var ipPat = /[\da-f]*([:\.]+[\da-f]+)+(::)?/gi;
			
			// Use that Regex to find all IPs (and some other things like durations: "24.45"ms)
			var ipCandidates = pingOutput.match(ipPat);
			
			// Check if all found matches that are actually IPs match the referenceIP
			for ( var i = 0; i < ipCandidates.length; i++) {
				
				// For each match check if it is a valid IP-Address using the native inet_pton-function
				var isValidIP = self.functions.inet_pton(self.types.PR_AF_INET, ipCandidates[i], addressBuf);
				if (isValidIP == 0) {
					isValidIP = self.functions.inet_pton(self.types.PR_AF_INET6, ipCandidates[i], addressBuf);
				}

				// If it IS a valid IP-address compare it with the referenceIP ...
				if (isValidIP == 1) {
					if(ipCandidates[i] != referenceIP){
						
						// ... and in case they are not equal free all allocated buffers and return it
						self.functions.free(addressBuf);		
						return ipCandidates[i];
					}
				}
			}

			// If no non-matching IP is found free all allocated buffers and return null
			self.functions.free(addressBuf);		
			return null;
		};
		

		/**
		 * Perform a ping on a Unix/Linux system. This is currently done by executing "ping"/"ping6" and reading its output. Depending on that output it is then decided if the ping reached the host, a intermediate hop or if an error occurred.
		 * 
		 * The command that will be executed is /bin/ping -c 1 -n -W 1 -t "ttl" "ip"
		 * 
		 * @param ip The IP-Address to ping
		 * @param ipVersion The version of the IP-Address (4 or 6)
		 * @param ttl The Time-To-Live of the ping that should be sent
		 * @returns "TARGET "+TargetIP if the target was reached, "HOP "+HopIP if an intermediate Host was reached or "NO_REPLY" if an error occurred during the execution of "ping"
		 */
		Crossbear.CBTracer.prototype.ping_linux = function ping_linux(ip, ipVersion, ttl) {

			// Execute ping and pipe its output
			var pipe = self.functions.popen("/bin/ping" + ((ipVersion == 6) ? "6" : "") + " -c 1 -n -W 1 -t " + ttl + " " + ip + " 2>&1", "r");
			if (pipe == 0) {
				cbFrontend.displayTechnicalFailure("CBTracer:ping_linux: popen failed.", true);
				return null;
			}

			// Read ping's output from the pipe
			var pingRawOutput = [];
			var currentChar = self.functions.fgetc(pipe);
			while (currentChar != -1) {
				pingRawOutput.push(currentChar);
				currentChar = self.functions.fgetc(pipe);
			}

			// Close the pipe
			if (self.functions.pclose(pipe) < 0) {
				cbFrontend.displayTechnicalFailure("CBTracer:ping_linux: pclose failed.", true);
				return null;
			}

			// Convert the output to a Javascript string
			var pingOutput = Crypto.charenc.Binary.bytesToString(Crossbear.jsArrayToUint8Array(pingRawOutput));

			// Check if all occurences of IPs inside the output match the IP that was pinged
			var firstNonMatchIP = self.getFirstNonMatchIP(pingOutput, ip);

			// Check if either the pattern "TTL" or "TIME TO LIVE" or "HOP LIMIT" appears
			var ttlPat = /TTL|TIME TO LIVE|HOP LIMIT/gi;
			var containsTTL = (-1 != pingOutput.search(ttlPat));

			// Check if the pattern "0%" (but not 100%) appears -> Indicates "no Packet loss" on unix systems
			var zeroPercentPat = /[^0]0%/gi;
			var containsZeroPercent = (-1 != pingOutput.search(zeroPercentPat));

			// If there was only the target's IP in the output and if the packet loss was 0% then the ping reached the target
			if ((firstNonMatchIP == null) && containsZeroPercent) {
				return "TARGET " + ip;
			
			// If there was more than one IP in the output and it also contained a pattern indicating that the TTL was exceeded then the ping reached an intermediate hop
			} else if ((firstNonMatchIP != null) && containsTTL) {
				return "HOP " + firstNonMatchIP;
			
			// All other cases mean that an error occurred.
			} else {
				return "NO_REPLY";
			}

		};

		/**
		 * Perform a ping on a Windows system. This is currently done by calling the crossbear.dll which will in turn use the IPHLPAPI.dll to perform pings.
		 * 
		 * Please Note: Calling the IPHLPAPI.dll directly is not possible due to the bug https://bugzilla.mozilla.org/show_bug.cgi?id=684017 (GetLastError not possible from ctypes)
		 * 
		 * @param ip The IP-Address to ping 
		 * @param ttl The Time-To-Live of the ping that should be sent
		 * @returns "TARGET "+TargetIP if the target was reached, "HOP "+HopIP if an intermediate Host was reached or "NO_REPLY" if an error occurred during the execution of "ping"
		 */
		Crossbear.CBTracer.prototype.ping_win = function ping_win(ip, ttl) {

			// Define a buffer to receive a UTF-16 string from native code
			var buffersize = 150;
			var wcharArray = ctypes.ArrayType(ctypes.jschar);
			var replyBuffer = new wcharArray(buffersize);

			// Try to execute a ping using crossbear.dll
			if (!self.functions.ping(ip, ttl, replyBuffer, buffersize)) {
				cbFrontend.displayTechnicalFailure("CBTracer:ping_win:  Execution failed: " + replyBuffer.readString(), true);
			}

			// Return the result of the ping command
			return replyBuffer.readString();
		};

		/**
		 * Perform a ping no matter what OS (i.e. call ping_win or ping_linux depending on the current os)
		 * 
		 * @param ip The IP-Address to ping
		 * @param ipVersion The version of the IP-Address (4 or 6)
		 * @param ttl The Time-To-Live of the ping that should be sent
		 * @returns "TARGET "+TargetIP if the target was reached, "HOP "+HopIP if an intermediate Host was reached or "NO_REPLY" if an error occurred during the execution of "ping"
		 */
		Crossbear.CBTracer.prototype.ping = function ping(ip, ipVersion, ttl) {
			
			if (self.osIsWin) {
				return self.ping_win(ip, ttl);

			} else {
				return self.ping_linux(ip, ipVersion, ttl);
			}

		};

		/**
		 * Perform a Traceroute on an IP. This function will call the CBTracer.ping-function with increasing TTL-values. The Trace returned by this function will consist of one line per measured hop. If more than one IP replied for the same TTL then
		 * the line will look like "IP1|IP2|...". If there was no reply from a HOP it won't be listed (and there will be no empty line either). This is because of the fact that between two HOPs that reply there could possibly be a lot of HOPs that didn't reply
		 * and didn't decrease the TTL-value anyway.
		 * 
		 * @param ip The IP-Address to trace
		 * @param ipVersion The version of the IP-Address (4 or 6)
		 * @returns The Traceroute in the format described above
		 */
		Crossbear.CBTracer.prototype.traceroute = function traceroute(ip, ipVersion) {
			var re = [];

			// Perform pings with an increasing TTL (starting at 1 and ending with self.MaxHops)
			hopLoop: for ( var hopNum = 1; hopNum <= self.MaxHops; hopNum++) {
				
				var samplesOfHop = [];
				// For each TTL perform samplesOfHop-many Pings and see if more than one host replies
				for ( var sampleNum = 0; sampleNum < self.samplesPerHop; sampleNum++) {

					// Perform a ping with a given TTL and see whether it reached the Target, a Hop or no host at all
					var pingResult = self.ping(ip, ipVersion, hopNum).split(" ");
					switch (pingResult[0]) {
					case "HOP":
						// If it reached a HOP add it to the current Hop's host-list (but don't add duplicates)
						if (samplesOfHop.indexOf(pingResult[1]) < 0) {
							samplesOfHop.push(pingResult[1]);
						}
						break;
					case "TARGET":
						// If it reached the Target we are done
						break hopLoop;
					case "NO_REPLY":
						break;
					default:
						cbFrontend.displayTechnicalFailure("CBTracer:traceroute: Recieved unexpected ping response: " + pingResult.join(" "),true);
					}
				}
				
				// For each HOP: Generate a "|"-seperated list of IPs that replied 
				if (samplesOfHop.length > 0) {
					re.push(samplesOfHop.join('|'));
				}
			}
			
			//Finally add the Target's IP to the list of Hops (which will be transformed in a "\n"-seperated list) and return the trace
			return (re.join('\n') + '\n' + ip).trim();
		};

		/**
		 * For the task of locating a Mitm the information of what PublicIP a client is on is very valuable while the information which private IP it uses is of no use at all.
		 * 
		 * This function removes all private IPs from the Traceroute's output and replaces them with the client's publicIP
		 * 
		 * @param ownPublicIP The client's publicIP
		 * @param tracerouteOutput The output of the CBTracer.traceroute-function
		 * @returns publicIP.concat(tracerouteOutput) but without private IPs
		 */
		Crossbear.CBTracer.prototype.addOwnPublicIPAndRemovePrivateIPs = function addOwnPublicIPAndRemovePrivateIPs(ownPublicIP, tracerouteOutput) {
			
			// Split up the tracerouteOutput into the HOP-lines
			var arrayOfHops = tracerouteOutput.split("\n");
			var cleanedArrayOfHops = [];

			// Go over all HOP-lines ...
			for ( var i = 0; i < arrayOfHops.length; i++) {

				// ... and split them up to get all the IPs contained in that lines.
				var elementsOfCurrentHop = arrayOfHops[i].split("|");
				var cleanedElementsOfCurrentHop = [];

				// Then go through all of that IPs
				for ( var j = 0; j < elementsOfCurrentHop.length; j++) {

					// And check if they are private
					if (!elementsOfCurrentHop[j].match(Crossbear.privateIPRegex)) {
						
						// If they are remove them
						cleanedElementsOfCurrentHop.push(elementsOfCurrentHop[j]);
					}

				}
				
				// After having finished the inspection of the HOP-line: rebuild it and add it to the cleaned output
				if (cleanedElementsOfCurrentHop.length > 0) {
					cleanedArrayOfHops.push(cleanedElementsOfCurrentHop.join("|"));
				}
			}

			// Take the cleaned output and append the client's public IP to it (cleanedArrayOfHops will always include the target's IP and therefore it will never be empty)
			return ownPublicIP + "\n" + cleanedArrayOfHops.join("\n");

		};

	}

};
