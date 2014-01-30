/* -*- js-indent-level: 8; -*- */
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
 * This file contains all Helper-functions and constants that are required by the Crossbear Firefox-Plugin.
 * 
 * @author Thomas Riedmaier
 */

if ((typeof Crossbear) == "undefined") {
	var Crossbear = {
			
		/**
		 * Concatenate all of an array's elements.
		 * 
		 * e.g.: 
		 * - An array of Strings will produce a long String 
		 * - An array of integer[]s will generate a long integer[].
		 * 
		 * @param arr The array to implode
		 * @returns The concatenation of the array's elements
		 */
		implodeArray : function(arr) {
			var re = [];
			for ( var i = 0; i < arr.length; i++) {
				re = re.concat(arr[i]);
			}
			return re;
		},

		/**
		 * Extract the Hostname-part of a String (it is assumed that it is an URL)
		 * 
		 * e.g.: 
		 * - https://encrypted.google.com/#sclient=psy-ab&hl=de&site=&source=hp&q=Crossbear -> encrypted.google.com 
		 * - ftp://ftp.somedomain.org -> ftp.somedomain.org
		 * 
		 * @param str The String to extract the Hostname from
		 * @returns The Hostname-part of "str"
		 */
		extractHostname : function(str) {
			var re = new RegExp('^(?:f|ht)tp(?:s)?\://([^/?&]+)', 'im');
			return str.match(re)[1].toString();
		},

		/**
		 * Check if a String starts with another String
		 * 
		 * @param str The String to check
		 * @param start The String for which will be checked if the beginning of "str" is equal to it.
		 * @returns True if "str" starts with "start" and false otherwise.
		 */
		startsWith : function(str, start) {
			return (str.match("^" + start) == start);
		},

		/**
		 * Check if a String ends with another String
		 * 
		 * @param str The String to check
		 * @param end The String for which will be checked if the end of "str" is equal to it.
		 * @returns True if "str" ends with "end" and false otherwise.
		 */
		endsWith : function(str, end) {
			return (str.match(end + "$") == end);
		},

		/**
		 * Convert a String into a Hex-String (e.g. aAb -> 614162)
		 * 
		 * Please note: The string that is passed to this function is allowed to have non-printable chars (like the String that will be generated when a base64-encoded binary is passed to window.atob())
		 * 
		 * @param ins The String to convert
		 * @returns The Hex-String representation of "ins"
		 */
		stringToHexString : function(ins) {
			var re = "";
			for ( var i = 0; i < ins.length; i++) {
				re += String('00' + ins.charCodeAt(i).toString(16)).slice(-2);
			}
			return re;
		},

		/**
		 * Create an exact copy of an object.
		 * 
		 * @param obj The object to copy
		 * @returns A copy of "obj"
		 */
		clone : function(obj) {
			return Object.create(obj);
		},
		
		/**
		 * Check whether a variable is a valid number
		 * 
		 * This code was created by the use of http://stackoverflow.com/questions/18082/validate-numbers-in-javascript-isnumeric
		 * 
		 * @param n The variable to check
		 * @returns true, if n is a valid number; otherwise false
		 */
		isNumber: function (n) {
			  return !isNaN(parseFloat(n)) && isFinite(n);
		},


		/**
		 * Get the byte[][]-representation of a certificate's certificate chain
		 * 
		 * @param certificate The certificate for which the certificate chain should be obtained
		 * @returns The byte[][]-representation of "certificate"'s certificate chain
		 */
		getCertChainBytes : function(certificate) {

			// Get the certificate chain
			var cc = certificate.getChain();

			// For each element of the certificate chain:
			var certChain = [];
			for ( var i = 0; i < cc.length; i++) {

				// Get a handle for the certificate ...
				var currentCert = cc.queryElementAt(i, Components.interfaces.nsIX509Cert);

				// ... get its bytes and push them to the output array
				var currentCertBytesLength = {};
				certChain.push(currentCert.getRawDER(currentCertBytesLength));

			}
			// Return the byte[][]-representation of "certificate"'s certificate chain
			return certChain;
		},
		
		/**
		 * Write a String to a File
		 * 
		 * This code was created by the use of https://developer.mozilla.org/en/Code_snippets/File_I%2F%2FO#Write_a_string
		 * 
		 * @param string The string to write
		 * @param file The nsIFile to write to
		 */
		writeStringToFile : function(string, file){
		    Components.utils.import("resource://gre/modules/NetUtil.jsm");  
		    Components.utils.import("resource://gre/modules/FileUtils.jsm");  
		      		      
		    // Open the file with FileUtils.MODE_WRONLY | FileUtils.MODE_CREATE | FileUtils.MODE_TRUNCATE  
		    var ostream = FileUtils.openSafeFileOutputStream(file)  
		      
		    // Create a converter that converts the string into a stream
		    var converter = Components.classes["@mozilla.org/intl/scriptableunicodeconverter"].createInstance(Components.interfaces.nsIScriptableUnicodeConverter);  
		    converter.charset = "UTF-8";  
		    var istream = converter.convertToInputStream(string);  
		      
		    // Copy the data from the istream to the ostream
		    NetUtil.asyncCopy(istream, ostream, function(status) {  
		      if (!Components.isSuccessCode(status)) { 
		    	// Something went wrong ...
		        return false;  
		      }  
		      
		      // String has been written to the file. 
		      return true;
		    });  
		},

		/**
		 * Check if two Javascript arrays are equal
		 * 
		 * This code was created by the use of http://codeasp.net/forums/asp-net-topics/clent-side-web-development/591/compare-2-arrays-in-javascript
		 * 
		 * @param x The first array
		 * @param y The second array
		 * @returns True if both arrays contain the same elements else false
		 */
		arrayCompare : function(x, y) {
			// For reference types:returns true if x and y points to same object
			if (x === y) {
				return true;
			}

			// Return false if they don't contain the same number of elements
			if (x.length != y.length) {
				return false;
			}

			// Since they contain the same number of elements: Check if all elements of x are also in y
			for (key in x) {
				if (x[key] !== y[key]) {// !== So that the the values are not converted while comparison
					return false;
				}
			}
			return true;
		},

		/**
		 * Convert the byte[]-representation of an IP-Address into it's String-representation
		 * 
		 * e.g.: 
		 * - {192,168,0,1} -> "192.168.0.1" 
		 * - {1,2,3,4,5,6,7,8,9,A,B,C,D,E,F,10} -> "0102:0304:0506:0708:090A:0B0C:0D0E:0F10"
		 * 
		 * Please note: This code works for IPv4-Addresses as well as for IPv6-Addresses
		 * 
		 * @param uint8ArrayIP The byte[]-representation of the IP-Address
		 * @returns The String-representation of uint8ArrayIP
		 */
		byteArrayIpToString : function(uint8ArrayIP) {

			var ipAddressParts = [];

			// Is the input supposed to be a IPv4-Address?
			if (uint8ArrayIP.length == 4) {

				// If yes: Create the "."-separated String-representation of a IPv4
				for ( var i = 0; i < 4; i++) {
					ipAddressParts.push(uint8ArrayIP[i].toString(10));
				}
				return ipAddressParts.join(".");

				// Is the input supposed to be a IPv6-Address?
			} else if (uint8ArrayIP.length == 16) {

				// If yes: Create the ":"-separated String representation of a IPv6
				for ( var i = 0; i < 16; i += 2) {
					ipAddressParts.push(String('00' + uint8ArrayIP[i].toString(16)).slice(-2) + String('00' + uint8ArrayIP[i + 1].toString(16)).slice(-2));
				}
				return ipAddressParts.join(":");

			} else
				return "";
		},

		/**
		 * Convert a normal Javascript array into a Uint8Array
		 * 
		 * For details about Uint8Arrays see https://developer.mozilla.org/en/JavaScript_typed_arrays/Uint8Array
		 * 
		 * @param jsArray The Javascript array to convert
		 * @returns The Uint8Array-representation of "jsArray"
		 */
		jsArrayToUint8Array : function(jsArray) {
			var uint8Array = new Uint8Array(jsArray.length);
			uint8Array.set(jsArray, 0);
			return uint8Array;
		},

		/**
		 * Convert a Uint8Array into a normal Javascript array
		 * 
		 * For details about Uint8Arrays see https://developer.mozilla.org/en/JavaScript_typed_arrays/Uint8Array
		 * 
		 * @param uint8Array The Uint8Array to convert
		 * @returns The Javascript-array-representation of "uint8Array"
		 */
		uint8ArrayToJSArray : function(uint8Array) {
			var jsArray = [];
			for ( var i = 0; i < uint8Array.length; i++) {
				jsArray.push(uint8Array[i]);
			}
			return jsArray;
		},

		/**
		 * Convert a byte[] of length 2 into a number
		 * 
		 * Please note: The byte[] is assumed to be in network byte-order (i.e. big-endian byte-order)
		 * 
		 * @param bytes The byte[] to convert
		 * @returns The number whose value is equal to "bytes" (interpreted in network byte-order)
		 */
		bytesToShort : function(bytes) {
			if (bytes.length != 2)
				return -1;

			return (bytes[0] << 8) + bytes[1];
		},

		/**
		 * Convert a byte[] of length 4 into a number
		 * 
		 * Please note: The byte[] is assumed to be in network byte-order (i.e. big-endian byte-order)
		 * 
		 * @param bytes The byte[] to convert
		 * @returns The number whose value is equal to "bytes" (interpreted in network byte-order)
		 */
		bytesToInt : function(bytes) {
			if (bytes.length != 4)
				return -1;

			// Since the "shifting-and-adding"-technique is not working for numbers close to the maximal Integer-value, the "convert-to-textual-representation-and-eval"-technique is used:
			var textualRepresentation = "0x";
			for ( var i = 0; i < bytes.length; i++) {
				textualRepresentation += ('00' + bytes[i].toString(16)).slice(-2);
			}

			// Convert the String representation of the number into a normal number
			return parseInt(textualRepresentation);
		},

		/**
		 * Convert an integer into a byte[] of length 4. The byte[] will be in network byte-order (i.e. big-endian byte-order)
		 * 
		 * @param int The Integer to convert
		 * @returns The byte[]-representation of "int"
		 */
		intToBytes : function(int) {

			return [ (int >>> 24) & 255, (int >>> 16) & 255, (int >>> 8) & 255, int & 255 ];
		},

		/**
		 * Convert a short integer into a byte[] of length 2. The byte[] will be in network byte-order (i.e. big-endian byte-order)
		 * 
		 * @param int The Integer to convert
		 * @returns The byte[]-representation of "int"
		 */
		shortToBytes : function(int) {

			return [ (int >>> 8) & 255, int & 255 ];
		},

		/**
		 * Extract the RSA-Public key from the base64-representation of a ASN.1-encoded certificate.
		 * 
		 * Please note: It is assumed that the key-length is 2048 bits
		 * 
		 * @param base64Cert A ASN.1-encoded certificate in base64-representation
		 * @returns A RSAKeyPair containing the Public-RSA-key (the Private RSA-key will not be set)
		 */
		getRSAPublicKeyFromBase64Cert : function(base64Cert) {

			// Finding the public key inside a certificate is equal to look for it's ASN.1 encoded identifier. A asn.1 encoded identifier of a 2048 bit RSA key looks like this:
			var asn1RSAKey2048Identifier = Crossbear.stringToHexString(window.atob("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"));
			var asn1Cert = Crossbear.stringToHexString(window.atob(base64Cert));

			// Search for the identifier inside the certificate and extract the adjacent modulus and exponent of the key
			var startOfModulus = asn1Cert.search(asn1RSAKey2048Identifier) + asn1RSAKey2048Identifier.length;
			var endOfModulus = startOfModulus + 2048 / 4;
			var startOfExponent = endOfModulus + 4;
			var endOfExponent = startOfExponent + 6;

			// Store the key data in a RSAKeyPair object (and call setMaxDigits which seems to be necessary to use the key in David Shapiro's RSA-implementation)
			Crossbear.RSA.BigInt.setMaxDigits(260);
			return new Crossbear.RSA.RSAKeyPair(asn1Cert.substring(startOfExponent, endOfExponent), "", asn1Cert.substring(startOfModulus, endOfModulus));
		},

		/**
		 * Read the certificate of the Crossbear server from the local file system and inform Crossbear's TDC (cbtrustdecisioncache) about the server's certificate. This is necessary to prevent Mitm-attacks against Crossbear (the Server's certificate
		 * that is set by this function is THE ONLY one that will be trusted for connections to the Crossbear server).
		 * 
		 * Finally this function will return the certificate's public key so it can be used to send asymmetrically encrypted data to the Crossbear server.
		 * 
		 * The code was created by the use of https://developer.mozilla.org/en/Code_snippets/Miscellaneous#Adding_custom_certificates_to_a_XULRunner_application
		 * 
		 * @param cbtrustdecisioncache The CBTrustDecisionCache to notify about the current Crossbear server certificate
		 * @returns A RSAKeyPair containing the Public-RSA-key of the Crossbear server
		 */
		loadCBCertAndAddToCache : function(cbtrustdecisioncache) {

			// Prepare to read the CBServer-certificate from the file system
			var scriptableStream = Cc["@mozilla.org/scriptableinputstream;1"].getService(Ci.nsIScriptableInputStream);
			var gIOService = Cc["@mozilla.org/network/io-service;1"].getService(Ci.nsIIOService);
			var channel = gIOService.newChannel("chrome://crossbear/content/certs/cbserver.crt", null, null);

			// Read the CBServer-certificate from the file system
			var input = channel.open();
			scriptableStream.init(input);
			var certfile = scriptableStream.read(input.available());
			scriptableStream.close();
			input.close();

			// Remove the header, the trailer and any linebreaks from the PEM-encoded certificate and put the rest into the "cert"-variable
			var beginCert = "-----BEGIN CERTIFICATE-----";
			var endCert = "-----END CERTIFICATE-----";
			certfile = certfile.replace(/[\r\n]/g, "");
			var begin = certfile.indexOf(beginCert);
			var end = certfile.indexOf(endCert);
			var cert = certfile.substring(begin + beginCert.length, end);

			// Notify the CBTrustDecisionCache about the current Crossbear server certificate
			var serverCertHash = Crypto.SHA256(Crypto.util.base64ToBytes(cert), {});
			cbtrustdecisioncache.setCBServerCertHash(serverCertHash);

			// Extract and return the certificate's public key
			return Crossbear.getRSAPublicKeyFromBase64Cert(cert);
		},

		/**
		 * Generate a random 256-bit AES-Key.
		 * 
		 * This code was created by the use of https://developer.mozilla.org/en/Code_snippets/Miscellaneous#Generating_Random_Bytes, according to which the used method is safe to generate a cryptographic key
		 * 
		 * @returns A byte[] of length 32 containing a 256-bit AES-Key
		 */
		generate256BitAESKey : function() {

			// 256 bit = 32 bytes
			const NOB = 32;

			// Load a secure random genarator and use it to generate 32 bytes of random data
			var prng = Components.classes['@mozilla.org/security/random-generator;1'];
			var aesKey = prng.getService(Components.interfaces.nsIRandomGenerator).generateRandomBytes(NOB, (new Date).getUTCMilliseconds());

			// Finally return it
			return aesKey;
		},

		/**
		 * Get the PEM-representation of a certificate.
		 * 
		 * Please note: The PEM encoding returned by this function is structured in lines of 64 characters each. Linebreaks are equal to a \n
		 * 
		 * @param cert The certificate
		 * @return The PEM representation of cert
		 */
		getPemEncoding : function(cert) {

			// Get the bytes of the certificate and encode them in base64
			var base64EncodedCert = Crypto.util.bytesToBase64(cert);

			// Write the PEM header
			var re = "-----BEGIN CERTIFICATE-----\n";

			// Write the certificate data in lines of 64 chars
			var len = base64EncodedCert.length;
			for ( var i = 0; i < len; i += 64) {
				re += base64EncodedCert.substring(i, Math.min(len, i + 64)) + "\n";
			}

			// Write the PEM trailer
			re += "-----END CERTIFICATE-----";

			// Return the PEM-representation of the certificate
			return re;
		},

		/**
		 * Calculate the Hash of a certificate chain. This is, concatenate the SHA256-hash of the server's certificate with the MD5-hashes of the chain certificates and calculate the SHA256-hash on the result
		 * 
		 * @param certChain The certificate chain to calculate the hash for (including the server certificate)
		 * @return The hash of the certificate chain
		 */
		calculateCertChainHash : function(certChain) {

			var certChainClone = Crossbear.clone(certChain);
			certChainClone.splice(0, 1);

			// Get the concatenation of the md5 hashes of the chain certificates ...
			var md5Hashes = [];
			for ( var i = 0; i < certChainClone.length; i++) {
				md5Hashes.push(Crypto.MD5(Crossbear.getPemEncoding(certChainClone[i]), {
					asBytes : true
				}));
			}
			var md5HashesConcat = Crossbear.implodeArray(md5Hashes);

			// Calculate the SHA256-hash of the server certificate
			var serverCertHash = Crypto.SHA256(certChain[0], {
				asBytes : true
			});

			// Concatenate the hash of the server certificate with the ones of its chain and calculate the SHA256-hash for the result
			return Crypto.SHA256(serverCertHash.concat(md5HashesConcat), {
				asBytes : true
			});
		},

		/**
		 * This function determines the pathes of the native libraries used by Crossbear. This has to be done by the GUI-Thread since it requires acces to priviledged operations.
		 * 
		 * Special thanks go to Moxie Marlinspike for showing me how to work with firefox internal libraries!
		 * 
		 * @param cbFrontend The cbFrontend-class that will be used to display information/errors
		 * @param osIsWin A flag indicating if the current system is a windows system
		 * @returns A object containing the pathes to the native libraries
		 */
		getLibPaths : function(cbFrontend, osIsWin) {

			// The object that will contain the libraries' pathes
			var libPaths = {};

			// Load the modules that are necessary to get the pathes of the c-type libraries
			Components.utils.import("resource://gre/modules/Services.jsm");
			Components.utils.import("resource://gre/modules/ctypes.jsm");

			/*
			 * First: Determine the pathes of the Firefox-libraries needed for the CBCertificateChainFetcher
			 */

			// Find the path of the NSS3-library
			try {
				// Get the path the library would have if it was in the Firefox folder
				var nssFile = Services.dirsvc.get("GreD", Components.interfaces.nsILocalFile);
				nssFile.append(ctypes.libraryName("nss3"));

				var nssLib = ctypes.open(nssFile.path);
				libPaths.nssLib = nssFile.path;
				nssLib.close();
			} catch (e) {
				// Try standard libary locations
				try {
					var nssLib = ctypes.open(ctypes.libraryName("nss3"));
					libPaths.nssLib = ctypes.libraryName("nss3");
					nssLib.close();
				} catch (e) {
					cbFrontend.displayTechnicalFailure("getLibPaths: Failed to open nss3-library", true);
				}
				;
			}

			// Find the path of the SSL3-library
			try {
				// Get the path the library would have if it was in the Firefox folder
				var sslFile = Services.dirsvc.get("GreD", Components.interfaces.nsILocalFile);
				sslFile.append(ctypes.libraryName("ssl3"));

				var sslLib = ctypes.open(sslFile.path);
				libPaths.sslLib = sslFile.path;
				sslLib.close();
			} catch (e) {
				// Try standard libary locations
				try {
					var sslLib = ctypes.open(ctypes.libraryName("ssl3"));
					libPaths.sslLib = ctypes.libraryName("ssl3");
					sslLib.close();
				} catch (e) {
					cbFrontend.displayTechnicalFailure("getLibPaths: Failed to open ssl3-library", true);
				}
				;
			}

			// Find the path of the NSPR4-library
			try {
				// Get the path the library would have if it was in the Firefox folder
				var nsprFile = Services.dirsvc.get("GreD", Components.interfaces.nsILocalFile);
				nsprFile.append(ctypes.libraryName("nspr4"));

				var nsprLib = ctypes.open(nsprFile.path);
				libPaths.nsprLib = nsprFile.path;
				nsprLib.close();
			} catch (e) {
				// Try standard libary locations
				try {
					var nsprLib = ctypes.open(ctypes.libraryName("nspr4"));
					libPaths.nsprLib = ctypes.libraryName("nspr4");
					nsprLib.close();
				} catch (e) {
					// Trying explicit FreeBSD path.
					try {
						var nsprLib = ctypes.open("/usr/local/lib/libnspr4.so");
						libPaths.nsprLib = "/usr/local/lib/libnspr4.so";
						nsprLib.close();
					} catch (e) {
						cbFrontend.displayTechnicalFailure("getLibPaths: Failed to open nspr4-library", true);
					}
					;
				}
				;
			}

			/*
			 * Second: Determine the pathes of the native-libraries needed for the CBTracer
			 */
			if (osIsWin) {

				// Find the path of the crossbear.dll
				var uri = Cc["@mozilla.org/network/io-service;1"].getService(Ci.nsIIOService).newURI('resource://CrossbearLIB', null, null);
				if (uri instanceof Components.interfaces.nsIFileURL) {

					try {
						var crossbearLib = ctypes.open(uri.file.path);
						libPaths.crossbearLib = uri.file.path;
						crossbearLib.close();
					} catch (e) {
						cbFrontend.displayTechnicalFailure("getLibPaths: Failed to open crossbear-library - "+uri.file.path, true);
					}
					;

				} else {
					cbFrontend.displayTechnicalFailure("getLibPaths: Failed to open crossbear-library - no uri", true);
				}

			} else {
				var uri_linux = Cc["@mozilla.org/network/io-service;1"].getService(Ci.nsIIOService).newURI('resource://CrossbearLIB_Linux', null, null);
				if (uri_linux instanceof Components.interfaces.nsIFileURL) {
					try {
						var crossbearLibLinux = ctypes.open(uri_linux.file.path);
						libPaths.crossbearLibLinux = uri_linux.file.path;
						crossbearLibLinux.close();
					} catch (e) {
						cbFrontend.displayTechnicalFailure("getLibPaths: Failed to open crossbear-linux library - " + uri_linux.file.path + ": " + e, true);
					}
					;
				} else {
					cbFrontend.displayTechnicalFailure("getLibPaths: Failed to open crossbear-linux library - no uri: " + e, true);
				}
			}
			
			return libPaths;
		},

		/**
		 * This function takes as input a byte[] representing an array of messages sent by the Crossbear-server. It decodes these messages and returns an array of CBMessages.
		 * 
		 * @param uint8Raw The byte[]-representation of an array of Messages
		 * @param cbFrontend The cbFrontend-class that will be used to display information/errors
		 * @returns An array of CBMessages which are the Javascript-representations of the Messages passed by the uint8Raw parameter
		 * 
		 * @author Thomas Riedmaier
		 */
		messageBuilder : function(uint8Raw, cbFrontend) {

			var decodedMessages = [];

			// Go through the array and read all of the contained messages. Therefore set the read pointer to the beginning og the message-array.
			var currentReadPos = 0;
			while (true) {

				// For each message extract the length field ...
				var currentMessageLength = Crossbear.bytesToShort([ uint8Raw[currentReadPos + 1], uint8Raw[currentReadPos + 2] ]);

				// ... and copy it's data to a new array (according to that length field)
				var messageData = uint8Raw.subarray(currentReadPos + 3, currentReadPos + currentMessageLength);

				// In case a invalid message was received the length-field might not be correct (i.e. the raw-data was not as long as the message-length-field claimed) -> catch this here
				if (messageData.length + 3 != currentMessageLength) {
					cbFrontend.displayTechnicalFailure("messageBuilder: tried to decode a message with invalid length parameter: " + messageData.length + " vs " + currentMessageLength, true);
				}

				// Read the message's type ...
				var typ = uint8Raw[currentReadPos];

				// ... and build a CBMessage-object depending on that type
				if (typ == Crossbear.CBMessageTypes.PUBLIC_IP_NOTIF4) {
					decodedMessages.push(new Crossbear.CBMessagePublicIPNotif(messageData, 4));

				} else if (typ == Crossbear.CBMessageTypes.PUBLIC_IP_NOTIF6) {
					decodedMessages.push(new Crossbear.CBMessagePublicIPNotif(messageData, 6));

				} else if (typ == Crossbear.CBMessageTypes.CURRENT_SERVER_TIME) {
					decodedMessages.push(new Crossbear.CBMessageCurrentServerTime(messageData));

				} else if (typ == Crossbear.CBMessageTypes.IPV4_SHA256_TASK) {
					decodedMessages.push(new Crossbear.CBMessageHuntingTask(messageData, 4));

				} else if (typ == Crossbear.CBMessageTypes.IPV6_SHA256_TASK) {
					decodedMessages.push(new Crossbear.CBMessageHuntingTask(messageData, 6));

				} else if (typ == Crossbear.CBMessageTypes.CERT_VERIFY_RESULT) {
					decodedMessages.push(new Crossbear.CBMessageCertVerifyResult(messageData));
				} else if (typ == Crossbear.CBMessageTypes.SIGNATURE) {
					decodedMessages.push(new Crossbear.CBMessageSignature(messageData))
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
		},
	/*	
		xmlToDOM : function (xml, doc, nodes) {  
			if (xml.length() != 1) {  
				 var domnode = doc.createDocumentFragment();  
				 for each (var child in xml)  
				 	domnode.appendChild(Crossbear.xmlToDOM(child, doc, nodes));  
				 return domnode;  
		    }  
			
			switch (xml.nodeKind()) {  
				case "text":  
					return doc.createTextNode(String(xml));
	                        // The following are the offending lines. They make use of E4X notation
                                // which Mozilla kindly dropped without offering a simple replacement.
                                // TODO: I replaced all E4X occurrences with DOMParser methods. Now,
 				// change this code to work on that instead E4X.
				case "element":  
					var domnode = doc.createElementNS(xml.namespace(), xml.localName());  
					for each (var attr in xml.@*::*)  
						domnode.setAttributeNS(attr.namespace(), attr.localName(), String(attr));  

					for each (var child in xml.*::*)  
						domnode.appendChild(Crossbear.xmlToDOM(child, doc, nodes));  
					if (nodes && "@key" in xml)  
						nodes[xml.@key] = domnode;  
					return domnode;  
				default:  
					return null;  
			}  
		}  */

	};
	
	// Regex that matches all IPv4 and all IPv6-Addresses (and more)
	Crossbear.ipRegex = /^[\d\.:abcdef]*$/i;

	// Regex that matches all IPv4-Addresses (and only these)
	Crossbear.ipv4Regex = /^0*([1-9]?\d|1\d\d|2[0-4]\d|25[0-5])\.0*([1-9]?\d|1\d\d|2[0-4]\d|25[0-5])\.0*([1-9]?\d|1\d\d|2[0-4]\d|25[0-5])\.0*(1\d\d|[1-9]?\d|2[0-4]\d|25[0-5])$/;

	// Regex that matches all IPv4 and IPv6 private IP-Addresses
	Crossbear.privateIPRegex = /^(fe8|fe9|fea|feb|fec|fed|fee|fef|fc|fd|169\.254\.|10\.|172\.16\.|172\.17\.|172\.18\.|172\.19\.|172\.20\.|172\.21\.|172\.22\.|172\.23\.|172\.24\.|172\.25\.|172\.26\.|172\.27\.|172\.28\.|172\.29\.|172\.30\.|172\.31\.|192\.168\.)/i;

};
