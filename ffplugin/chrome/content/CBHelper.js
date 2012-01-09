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
 * This file contains all Helper-functions and constants that are required by the Crossbear Firefox-Plugin.
 * 
 * @author Thomas Riedmaier
 */

/**
 * Concatenate all of the array's elements.
 * 
 * e.g.:
 * - An array of Strings will produce a long String
 * - An array of integer[]s will generate a long integer[].
 * 
 * @returns The concatenation of the array's elements
 */
Array.prototype.implode = function() {
	var re = [];
	for(var i = 0;i<this.length;i++){
		re = re.concat(this[i]);
	}
	return re;
};

/**
 * Get the Hostname-part of this String (it is assumed that it is an URL)
 * 
 * e.g.:
 * - https://encrypted.google.com/#sclient=psy-ab&hl=de&site=&source=hp&q=Crossbear -> encrypted.google.com
 * - ftp://ftp.somedomain.org -> ftp.somedomain.org
 *
 * @returns The Hostname-part of this String
 */
String.prototype.getHostname = function() {
	var re = new RegExp('^(?:f|ht)tp(?:s)?\://([^/]+)', 'im');
	return this.match(re)[1].toString();
};

/**
 * Check if this String starts with another String
 * 
 * @param str The String for which will be checked if the beginning of this String is equal to it.
 * @returns True if this String starts with "str" and false otherwise.
 */
String.prototype.startsWith = function(str) {
	return (this.match("^" + str) == str);
};

/**
 * Check if this String ends with another String
 * 
 * @param str The String for which will be checked if the end of this String is equal to it.
 * @returns True if this String ends with "str" and false otherwise.
 */
String.prototype.endsWith = function(str) {
	return (this.match(str + "$") == str);
};

// Regex that matches all IPv4 and all IPv6-Addresses (and more)
const ipRegex = /^[\d\.:abcdef]*$/i;

// Regex that matches all IPv4-Addresses (and only these)
const ipv4Regex = /^0*([1-9]?\d|1\d\d|2[0-4]\d|25[0-5])\.0*([1-9]?\d|1\d\d|2[0-4]\d|25[0-5])\.0*([1-9]?\d|1\d\d|2[0-4]\d|25[0-5])\.0*(1\d\d|[1-9]?\d|2[0-4]\d|25[0-5])$/;

// Regex that matches all IPv4 and IPv6 private IP-Addresses
const privateIPRegex = /^(fe8|fe9|fea|feb|fec|fed|fee|fef|fc|fd|169\.254\.|10\.|172\.16\.|172\.17\.|172\.18\.|172\.19\.|172\.20\.|172\.21\.|172\.22\.|172\.23\.|172\.24\.|172\.25\.|172\.26\.|172\.27\.|172\.28\.|172\.29\.|172\.30\.|172\.31\.|192\.168\.)/i;

/**
 * Convert a String into a Hex-String (e.g. aAb -> 614162)
 * 
 * Please note: The string that is passed to this function is allowed to have non-printable chars (like the String that will be generated when a base64-encoded binary is passed to window.atob())
 * 
 * @param ins The String to convert
 * @returns The Hex-String representation of "ins"
 */
function stringToHexString(ins) {
	var re = "";
	for ( var i = 0; i < ins.length; i++) {
		re += String('00' + ins.charCodeAt(i).toString(16)).slice(-2);
	}
	return re;
}

/**
 * Create an exact copy of an object.
 * @param obj The object to copy
 * @returns A copy of "obj"
 */
function clone(obj) {
	return eval(uneval(obj));
};

/**
 * Get the byte[][]-representation of a certificate's certificate chain
 * 
 * @param certificate The certificate for which the certificate chain should be obtained
 * @returns The byte[][]-representation of "certificate"'s certificate chain
 */
function getCertChainBytes(certificate) {

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
};

/**
 * Check if two Javascript arrays are equal
 * 
 * This code was created by the use of http://codeasp.net/forums/asp-net-topics/clent-side-web-development/591/compare-2-arrays-in-javascript
 *
 * @param x The first array
 * @param y The second array
 * @returns True if both arrays contain the same elements else false
 */
function arrayCompare(x, y) {
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
}

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
function byteArrayIpToString(uint8ArrayIP) {

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
}

/**
 * Convert a normal Javascript array into a Uint8Array
 * 
 * For details about Uint8Arrays see https://developer.mozilla.org/en/JavaScript_typed_arrays/Uint8Array
 * 
 * @param jsArray The Javascript array to convert
 * @returns The Uint8Array-representation of "jsArray"
 */
function jsArrayToUint8Array(jsArray) {
	var uint8Array = new Uint8Array(jsArray.length);
	uint8Array.set(jsArray, 0);
	return uint8Array;
}

/**
 * Convert a Uint8Array into a normal Javascript array
 * 
 * For details about Uint8Arrays see https://developer.mozilla.org/en/JavaScript_typed_arrays/Uint8Array
 * 
 * @param uint8Array The Uint8Array to convert
 * @returns The Javascript-array-representation of "uint8Array"
 */
function uint8ArrayToJSArray(uint8Array) {
	var jsArray = [];
	for ( var i = 0; i < uint8Array.length; i++) {
		jsArray.push(uint8Array[i]);
	}
	return jsArray;
}

/**
 * Convert a byte[] of length 2 into a number
 * 
 * Please note: The byte[] is assumed to be in network byte-order (i.e. big-endian byte-order) 
 * 
 * @param bytes The byte[] to convert
 * @returns The number whose value is equal to "bytes" (interpreted in network byte-order)
 */
function bytesToShort(bytes) {
	if (bytes.length != 2)
		return -1;

	return (bytes[0] << 8) + bytes[1];
}

/**
 * Convert a byte[] of length 4 into a number
 * 
 * Please note: The byte[] is assumed to be in network byte-order (i.e. big-endian byte-order) 
 * 
 * @param bytes The byte[] to convert
 * @returns The number whose value is equal to "bytes" (interpreted in network byte-order)
 */
function bytesToInt(bytes) {
	if (bytes.length != 4)
		return -1;

	// Since the "shifting-and-adding"-technique is not working for numbers close to the maximal Integer-value, the "convert-to-textual-representation-and-eval"-technique is used:
	var textualRepresentation = "0x";
	for(var i = 0; i< bytes.length;i++){
		textualRepresentation += ('00' + bytes[i].toString(16)).slice(-2);
	}
	
	// Evaluate the String representation of the number and thus convert it to a normal number
	return eval(textualRepresentation);
}

/**
 * Convert an integer into a byte[] of length 4. The byte[] will be in network byte-order (i.e. big-endian byte-order)
 * 
 * @param int The Integer to convert
 * @returns The byte[]-representation of "int"
 */
function intToBytes(int) {

	return [ (int >>> 24) & 255, (int >>> 16) & 255, (int >>> 8) & 255, int & 255 ];
}

/**
 * Convert a short integer into a byte[] of length 2. The byte[] will be in network byte-order (i.e. big-endian byte-order)
 * 
 * @param int The Integer to convert
 * @returns The byte[]-representation of "int"
 */
function shortToBytes(int) {

	return [(int >>> 8) & 255, int & 255 ];
}

/**
 * Extract the RSA-Public key from the base64-representation of a ASN.1-encoded certificate.
 * 
 * Please note: It is assumed that the key-length is 2048 bits
 * 
 * @param base64Cert A ASN.1-encoded certificate in base64-representation
 * @returns A RSAKeyPair containing the Public-RSA-key (the Private RSA-key will not be set)
 */
function getRSAPublicKeyFromBase64Cert(base64Cert) {
	
	// Finding the public key inside a certificate is equal to look for it's ASN.1 encoded identifier. A asn.1 encoded identifier of a 2048 bit RSA key looks like this:
	var asn1RSAKey2048Identifier = stringToHexString(window.atob("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"));
	var asn1Cert = stringToHexString(window.atob(base64Cert));

	// Search for the identifier inside the certificate and extract the adjacent modulus and exponent of the key
	var startOfModulus = asn1Cert.search(asn1RSAKey2048Identifier) + asn1RSAKey2048Identifier.length;
	var endOfModulus = startOfModulus + 2048 / 4;
	var startOfExponent = endOfModulus + 4;
	var endOfExponent = startOfExponent + 6;

	// Store the key data in a RSAKeyPair object (and call setMaxDigits which seems to be necessary to use the key in David Shapiro's RSA-implementation)
	setMaxDigits(260);
	return new RSAKeyPair(asn1Cert.substring(startOfExponent, endOfExponent), "", asn1Cert.substring(startOfModulus, endOfModulus));
}

/**
 * Read the certificate of the Crossbear server from the local file system and add it as a trusted server certificate to the Firefox certificate database. This needs to be done since Firefox doesn't allow connections to servers whose certificates it
 * doesn't trust. After this is done Crossbear's own Certificate cache (cbcertificatecache) is informed about the server's certificate. This again is necessary to prevent Mitm-attacks against Crossbear (the Server's certificate that is set by this
 * function is THE ONLY one that will be trusted for connections to the Crossbear server).
 * 
 * Finally this function will return the certificate's public key so it can be used to send asymmetrically encrypted data to the Crossbear server.
 * 
 * The code was created by the use of https://developer.mozilla.org/en/Code_snippets/Miscellaneous#Adding_custom_certificates_to_a_XULRunner_application
 * 
 * @param cbcertificatecache The CBCertificateCache to notify about the current Crossbear server certificate
 * @returns A RSAKeyPair containing the Public-RSA-key of the Crossbear server
 */
function addCBCertToLocalStoreAndCache(cbcertificatecache) {
	
	// Open Firefox's certificate database
	var certDB = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB2);
	
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
	
	// Add the certificate to Firefox's certificate database
	certDB.addCertFromBase64(cert, 'P,p,p', "");

	// Notify the CBCertificateCache about the current Crossbear server certificate
	var serverCertHash = Crypto.SHA256(Crypto.util.base64ToBytes(cert), {});
	cbcertificatecache.setCBServerCertHash(serverCertHash);

	// Extract and return the certificate's public key
	return getRSAPublicKeyFromBase64Cert(cert);
}

/**
 * Generate a random 256-bit AES-Key.
 * 
 * This code was created by the use of https://developer.mozilla.org/en/Code_snippets/Miscellaneous#Generating_Random_Bytes, according to which the used method is safe to generate a cryptographic key
 * 
 * @returns A byte[] of length 32 containing a 256-bit AES-Key
 */
function generate256BitAESKey() {

	// 256 bit = 32 bytes
	const NOB = 32;
	
	// Load a secure random genarator and use it to generate 32 bytes of random data
	var prng = Components.classes['@mozilla.org/security/random-generator;1'];
	var aesKey = prng.getService(Components.interfaces.nsIRandomGenerator).generateRandomBytes(NOB, (new Date).getUTCMilliseconds());
	
	// Finally return it
	return aesKey;
};

/**
 * This function determines the pathes of the native libraries used by Crossbear. This has to be done by the GUI-Thread since it requires acces to priviledged operations.
 *
 * Special thanks go to Moxie Marlinspike for showing me how to work with firefox internal libraries!
 *
 * @param cbFrontend The cbFrontend-class that will be used to display information/errors
 * @param osIsWin A flag indicating if the current system is a windows system
 * @returns A object containing the pathes to the native libraries
 */
function getLibPaths(cbFrontend, osIsWin) {

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
		};
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
		};
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
			};
		};
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
				cbFrontend.displayTechnicalFailure("getLibPaths: Failed to open crossbear-library", true);
			};

		} else {
			cbFrontend.displayTechnicalFailure("getLibPaths: Failed to open crossbear-library", true);
		};

	} else {
		
		// Find the path of the c-library
		try {
			var cLib = ctypes.open(ctypes.libraryName("c"));
			libPaths.cLib = ctypes.libraryName("c");
			cLib.close();
		} catch (e) {
			try {
				var cLib = ctypes.open("libc.so.6");
				libPaths.cLib = "libc.so.6";
				cLib.close();
			} catch (e) {
				cbFrontend.displayTechnicalFailure("getLibPaths: Failed to open c-library", true);
			};
		};
	}

	return libPaths;

};

