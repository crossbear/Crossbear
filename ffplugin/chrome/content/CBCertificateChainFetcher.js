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
 * The CBCertificateChainFetcher provides the functionality to download certificate chains from SSL/TLS-enabled servers. It is able to 
 * - connect to a SPECIFIC IP (not only to SOME ip of a domain)
 * - connect to a SPECIFIC domain of an IP (i.e. use the SNI-extension)
 * - connect to systems that require the "SSLv2Hello"-Protocol (these systems are incompatible with the normal TLS/SSLv3)
 * 
 * Please note: With CBCertificateChainFetcher it is possible to connect to a SPECIFIC domain of a SPECIFIC IP (Firefox's standard method allows merely to set one of that parameters at the same time)
 * 
 * @param cbFrontend The cbFrontend-class that will be used to display information/errors
 * 
 * @author Thomas Riedmaier
 */
Crossbear.CBCertificateChainFetcher = function (cbFrontend) {
	this.cbFrontend = cbFrontend;
	
	// Container for opened libraries
	this.libs = null;
	
	// Container for defined c-types
	this.types = null;
	
	// Container for defined c-type-functions
	this.functions = null;

	// "this" does not always point to THIS object (especially in callback functions). Therefore I use the "self" variable to hold a handle on THIS object
	var self = this;

	// Initialize the member function references for the class prototype (like this it's only done once and not every time a instance of this object is created)
	if (typeof (_crossbear_certificatechainfetcher_prototype_called) == 'undefined') {
		_crossbear_certificatechainfetcher_prototype_called = true;
		
		/**
		 * Open the native libraries required to connect to a server and to get its certificate chain (nss3-library, ssl3-library and nspr4-library. All these are shipped with Firefox)
		 * 
		 * @param libs The container that will hold the references to the libraries once they are opened
		 * @param libPaths The container that holds the paths of the native libraries
		 */
		Crossbear.CBCertificateChainFetcher.prototype.openFFLibraries = function openFFLibraries(libs, libPaths) {

			// Load the nss3-library 
			try {
				libs.nssLib = ctypes.open(libPaths.nssLib);
			} catch (e) {
				cbFrontend.displayTechnicalFailure("CBCertificateChainFetcher: Failed to open nss3-library: "+libPaths.nssLib,true);
				return false;
			}

			// Load the ssl3-library
			try {
				libs.sslLib = ctypes.open(libPaths.sslLib);
			} catch (e) {
				cbFrontend.displayTechnicalFailure("CBCertificateChainFetcher: Failed to open ssl3-library: "+libPaths.sslLib,true);
				return false;
			}

			// Load the nspr4-library
			try {
				libs.nsprLib = ctypes.open(libPaths.nsprLib);
			} catch (e) {
				cbFrontend.displayTechnicalFailure("CBCertificateChainFetcher: Failed to open nspr4-library: "+libPaths.nsprLib,true);
				return false;
			}
			
			return true;
		};
		
		/**
		 * Define the c-types used by the function-calls to the native libraries
		 * 
		 * @param types The container that will hold these c-type definitions
		 * @param osIsWin A flag indicating whether the current system is a Windows system or not
		 */
		Crossbear.CBCertificateChainFetcher.prototype.defineFFLibTypes = function defineFFLibTypes(types, osIsWin) {
			
			// Boolean constants
			types.PR_TRUE = 1;
			types.PR_FALSE = 0;
			
			// PRStatus (see http://doxygen.db48x.net/mozilla-full/html/dc/d23/prtypes_8h.html)
			types.PR_FAILURE = -1;
			types.PR_SUCCESS = 0;
			
			//SECStatus (see http://zenit.senecac.on.ca/wiki/dxr/source.cgi/mozilla/security/nss/lib/util/seccomon.h)
			types.SECWouldBlock = -2;
			types.SECFailure = -1;
			types.SECSuccess = 0;
			
			//Some Options for SSL_OptionSet (see http://zenit.senecac.on.ca/wiki/dxr/source.cgi/mozilla/security/nss/lib/ssl/ssl.h)
			types.SSL_ENABLE_SSL3 = 8;
			types.SSL_ENABLE_TLS = 13;
			
			//Some SSL Errorcodes (see http://www.mozilla.org/projects/security/pki/nss/ref/ssl/sslerr.html)
			types.SSL_ERROR_ILLEGAL_PARAMETER_ALERT = -12226;
			types.SSL_ERROR_RX_RECORD_TOO_LONG = -12263;
			 
			//PRShutdownHow (see http://doxygen.db48x.net/mozilla-full/html/da/d32/prio_8h.html)
			types.PR_SHUTDOWN_RCV = 0;
			types.PR_SHUTDOWN_SEND = 1;
			types.PR_SHUTDOWN_BOTH = 2;
			
			//TCP address families (Depend on whether the current system is a Windows or not)
			types.PR_AF_INET = 2;
			types.PR_AF_INET6 = osIsWin?23:10;
			
			// Defining all of the used structs inflates the source code a lot and is not necessary. Therefore I only define the structs that are actually necessary. All others will be represented by "someStruct" which is a generic struct.
			types.someStruct = ctypes.StructType("someStruct");
			
			// See http://doxygen.db48x.net/mozilla-full/html/df/d61/structSECItemStr.html
			types.SECItem = ctypes.StructType("SECItem",
						[{'type' : ctypes.int},
		                 {'data' : ctypes.unsigned_char.ptr},
		                 {'len' : ctypes.uint32_t}]);
			
			// See http://doxygen.db48x.net/mozilla-full/html/d9/d77/structSECAlgorithmIDStr.html
			types.SECAlgorithmID = ctypes.StructType("SECAlgorithmID",
				       [{'algorithm' : types.SECItem},
		                {'parameters' : types.SECItem}]);
			
			// See http://doxygen.db48x.net/mozilla-full/html/d8/dc9/structCERTSubjectPublicKeyInfoStr.html
			types.CERTSubjectPublicKeyInfo = ctypes.StructType("CERTSubjectPublicKeyInfo",
						 [{'arena' : types.someStruct.ptr},
		                  {'algorithm' : types.SECAlgorithmID},
		                  {'subjectPublicKey' : types.SECItem}]);
			
			// See http://doxygen.db48x.net/mozilla-full/html/db/d4a/structCERTSignedDataStr.html
			types.CERTSignedData  = ctypes.StructType("CERTSignedData",
				       [{'data' : types.SECItem},
		                {'signatureAlgorithm' : types.SECAlgorithmID},
		                {'signature' : types.SECItem}]);
			
			// See http://doxygen.db48x.net/mozilla-full/html/d9/db1/structCERTNameStr.html
			types.CERTName  = ctypes.StructType("CERTName",
						 [{'arena' : types.someStruct.ptr},
		                  {'rdns' : types.someStruct.ptr.ptr}]);
			
			// See http://doxygen.db48x.net/mozilla-full/html/d1/d15/structCERTValidityStr.html
			types.CERTValidity = ctypes.StructType("CERTValidity",
					     [{'arena' : types.someStruct.ptr},
		                  {'notBefore' : types.SECItem},
		                  {'notAfter' : types.SECItem}]);
			
			// See http://doxygen.db48x.net/mozilla-full/html/dc/d94/structCERTCertificateStr.html
			types.CERTCertificate = ctypes.StructType("CERTCertificate",
						[{'arena' : types.someStruct.ptr},
		                 {'subjectName' : ctypes.char.ptr},
		                 {'issuerName' : ctypes.char.ptr},
		                 {'signatureWrap' : types.CERTSignedData},
		                 {'derCert' : types.SECItem},
		                 {'derIssuer' : types.SECItem},
		                 {'derSubject' : types.SECItem},
		                 {'derPublicKey' : types.SECItem},
		                 {'certKey' : types.SECItem},
		                 {'version' : types.SECItem},
		                 {'serialNumber' : types.SECItem},
		                 {'signature' : types.SECAlgorithmID},
		                 {'issuer' : types.CERTName},
		                 {'validity' : types.CERTValidity},
		                 {'subject' : types.CERTName},
		                 {'subjectPublicKeyInfo' : types.CERTSubjectPublicKeyInfo},
		                 {'issuerID' : types.SECItem},
		                 {'subjectID' : types.SECItem},
		                 {'extensions' : types.someStruct.ptr.ptr},
		                 {'emailAddr' : ctypes.char.ptr},					 
		                 {'dbhandle' : types.someStruct.ptr},
		                 {'subjectKeyID' : types.SECItem},
		                 {'keyIDGenerated' : ctypes.char},
		                 {'keyUsage' : ctypes.unsigned_int},
		                 {'rawKeyUsage' : ctypes.unsigned_int},
		                 {'keyUsagePresent' : ctypes.char},
		                 {'nsCertType' : ctypes.uint32_t},
		                 {'keepSession' : ctypes.char},
		                 {'timeOK' : ctypes.char},
		                 {'domainOK' : types.someStruct.ptr},
		                 {'isperm' : ctypes.char},
		                 {'istemp' : ctypes.char},
		                 {'nickname' : ctypes.char.ptr},
		                 {'dbnickname' : ctypes.char.ptr},
		                 {'nssCertificate' : types.someStruct.ptr},
		                 {'trust' : types.someStruct.ptr},
		                 {'referenceCount' : ctypes.int},
		                 {'subjectList' : types.someStruct.ptr},
		                 {'authKeyID' : types.someStruct.ptr},
		                 {'isRoot' : ctypes.char},
		                 {'options' : ctypes.voidptr_t},
		                 {'series' : ctypes.int},
		                 {'slot' : types.someStruct.ptr},
		                 {'pkcs11ID' : ctypes.long},
		                 {'ownSlot' : ctypes.char}]);
			
			// Define a ssl-hook-callback-function-type (Thanks go to Moxie Marlinspike for showing me how to do that) 
			types.SSL_AuthCertificate = ctypes.FunctionType(ctypes.default_abi, 
					 ctypes.int32_t, 
					 [ctypes.voidptr_t,
						 types.someStruct.ptr,
						 ctypes.char,
						 ctypes.char]).ptr;
			
			/* 
			 * See http://doxygen.db48x.net/mozilla-full/html/d1/d31/structPRCListStr.html
			 * 
			 * Defines in the Firefox sources related to this type:
			 * #define PR_LIST_HEAD(_l) (_l)->next
			 * #define PR_LIST_TAIL(_l) (_l)->prev
			 */
			types.PRCList  = ctypes.StructType("PRCList",
						 [{'next' : ctypes.voidptr_t},
						  {'prev' : ctypes.voidptr_t}]);
			
			/* 
			 * See http://doxygen.db48x.net/mozilla-full/html/dc/d77/structCERTCertListNodeStr.html and http://mxr.mozilla.org/security/source/security/nss/lib/certdb/certt.h#378
			 * 
			 * Defines in the Firefox sources related to this type:
			 * #define CERT_LIST_HEAD(l) ((CERTCertListNode *)PR_LIST_HEAD(&l->list))
			 * #define CERT_LIST_NEXT(n) ((CERTCertListNode *)n->links.next)
			 * #define CERT_LIST_END(n,l) (((void *)n) == ((void *)&l->list))
			 * #define CERT_LIST_EMPTY(l) CERT_LIST_END(CERT_LIST_HEAD(l), l)
			 */
			types.CERTCertListNode  = ctypes.StructType("CERTCertListNode",
					 [{'links' : types.PRCList},
						 {'cert' : types.CERTCertificate.ptr},
						 {'appData' : ctypes.voidptr_t},
						 ]);
			
			// See http://mxr.mozilla.org/security/source/security/nss/lib/certdb/certt.h#378
			types.CERTCertList  = ctypes.StructType("CERTCertList",
					  [{'list' : types.PRCList},
						  {'arena' : types.someStruct.ptr}]);
		};

		/**
		 * Define the c-type-functions used within the CBCertificateChainFetcher class
		 * 
		 * @param functions The container that will hold these c-type definitions
		 * @param types The container that contains the c-type-definitions
		 * @param libs The container that contains references to the native libraries
		 */
		Crossbear.CBCertificateChainFetcher.prototype.defineFFlibFunctions = function defineFFlibFunctions(functions, types, libs) {
			
			// See https://developer.mozilla.org/en/PR_calloc
			functions.PR_Calloc = libs.nsprLib.declare("PR_Calloc",
					  ctypes.default_abi,
					  ctypes.voidptr_t,
					  ctypes.uint32_t,
					  ctypes.uint32_t);
			
			// See https://developer.mozilla.org/en/PR_FREE
			functions.PR_Free = libs.nsprLib.declare("PR_Free",
					  ctypes.default_abi,
					  ctypes.void_t,
					  ctypes.voidptr_t);
			
			/*
			 * See https://developer.mozilla.org/en/PR_GetError 
			 * Error codes are listed on http://zenit.senecac.on.ca/wiki/dxr/source.cgi/mozilla/nsprpub/pr/include/prerr.h
			 */ 
			functions.PR_GetError = libs.nsprLib.declare("PR_GetError",
					  ctypes.default_abi,
					  ctypes.int);
			
			// See https://developer.mozilla.org/en/PR_OpenTCPSocket
			functions.PR_OpenTCPSocket = libs.nsprLib.declare("PR_OpenTCPSocket", 
					  ctypes.default_abi, 
					  types.someStruct.ptr,
					  ctypes.int32_t);
		 
			// See https://developer.mozilla.org/en/PR_Connect
			functions.PR_Connect = libs.nsprLib.declare("PR_Connect",
					  ctypes.default_abi,
					  ctypes.int32_t,
					  types.someStruct.ptr,
					  types.someStruct.ptr,
					  ctypes.uint32_t);
		 
			// See https://developer.mozilla.org/en/PR_Close
			functions.PR_Close = libs.nsprLib.declare("PR_Close",
					  ctypes.default_abi,
					  ctypes.int32_t,
					  types.someStruct.ptr);

			// See https://developer.mozilla.org/en/PR_Shutdown
			functions.PR_Shutdown = libs.nsprLib.declare("PR_Shutdown",
					  ctypes.default_abi,
					  ctypes.int32_t,
					  types.someStruct.ptr, 
					  ctypes.int32_t);
			
			// See https://developer.mozilla.org/en/PR_StringToNetAddr
			functions.PR_StringToNetAddr = libs.nsprLib.declare("PR_StringToNetAddr",
					  ctypes.default_abi,
					  ctypes.int32_t,
					  ctypes.char.ptr,
					  types.someStruct.ptr);
			  
			// See https://developer.mozilla.org/en/PR_InitializeNetAddr
			functions.PR_InitializeNetAddr = libs.nsprLib.declare("PR_InitializeNetAddr",
					  ctypes.default_abi,
					  ctypes.int32_t,
					  ctypes.int,
					  ctypes.uint16_t,
					  types.someStruct.ptr);
			
			// See https://developer.mozilla.org/en/PR_SecondsToInterval
			functions.PR_SecondsToInterval = libs.nsprLib.declare("PR_SecondsToInterval",
					  ctypes.default_abi,
					  ctypes.uint32_t,
					  ctypes.uint32_t);
			
			// See http://www.mozilla.org/projects/security/pki/nss/ref/ssl/sslfnc.html#1085950
			functions.SSL_ImportFD = libs.sslLib.declare("SSL_ImportFD",
					  ctypes.default_abi,
					  types.someStruct.ptr,
					  types.someStruct.ptr,
					  types.someStruct.ptr);
			
			// See http://www.mozilla.org/projects/security/pki/nss/ref/ssl/sslfnc.html#1087792
			functions.SSL_SetURL = libs.sslLib.declare("SSL_SetURL",
					  ctypes.default_abi,
					  ctypes.int32_t,
					  types.someStruct.ptr,
					  ctypes.char.ptr);
			
			/*
			 *  See http://www.mozilla.org/projects/security/pki/nss/ref/ssl/sslfnc.html#1086543
			 *  and http://zenit.senecac.on.ca/wiki/dxr/source.cgi/mozilla/security/nss/lib/ssl/sslsock.c
			 *  Option codes can be found here: http://zenit.senecac.on.ca/wiki/dxr/source.cgi/mozilla/security/nss/lib/ssl/ssl.h
			 */
			functions.SSL_OptionSet = libs.sslLib.declare("SSL_OptionSet",
					  ctypes.default_abi,
					  ctypes.int,
					  types.someStruct.ptr, 
					  ctypes.int32_t, 
					  ctypes.char);
			
			// See http://www.mozilla.org/projects/security/pki/nss/ref/ssl/sslfnc.html#1088805
			functions.SSL_AuthCertificateHook = libs.sslLib.declare("SSL_AuthCertificateHook",
					  ctypes.default_abi,
					  ctypes.int32_t,
					  types.someStruct.ptr,
					  types.SSL_AuthCertificate,
					  ctypes.voidptr_t);
			  

			// See http://www.mozilla.org/projects/security/pki/nss/ref/ssl/sslfnc.html#1058001
			functions.SSL_ResetHandshake = libs.sslLib.declare("SSL_ResetHandshake",
					  ctypes.default_abi,
					  ctypes.int32_t,
					  types.someStruct.ptr,
					  ctypes.char);

			// See http://www.mozilla.org/projects/security/pki/nss/ref/ssl/sslfnc.html#1133431 but with additional timeout parameter
			functions.SSL_ForceHandshakeWithTimeout = libs.sslLib.declare("SSL_ForceHandshakeWithTimeout",
					  ctypes.default_abi,
					  ctypes.int32_t,
					  types.someStruct.ptr,
					  ctypes.uint32_t);
			  
			// See http://www.mozilla.org/projects/security/pki/nss/ref/ssl/sslfnc.html#1096168
			functions.SSL_PeerCertificate = libs.sslLib.declare("SSL_PeerCertificate",
					  ctypes.default_abi,
					  types.CERTCertificate.ptr,
					  types.someStruct.ptr);
			
			// See http://www.mozilla.org/projects/security/pki/nss/ref/ssl/sslcrt.html#1050532
			functions.CERT_DestroyCertificate = libs.nssLib.declare("CERT_DestroyCertificate",
					  ctypes.default_abi,
					  ctypes.void_t,
					  types.CERTCertificate.ptr);
			
			// See https://developer.mozilla.org/en/PR_Now
			functions.PR_Now = libs.nsprLib.declare("PR_Now",
					  ctypes.default_abi,
					  ctypes.int64_t);
		 
			/*
			 *  See http://zenit.senecac.on.ca/wiki/dxr/source.cgi/mozilla/security/nss/lib/certhigh/certvfy.c
			 *  and http://zenit.senecac.on.ca/wiki/dxr/source.cgi/mozilla/security/manager/ssl/src/nsNSSCertificate.cpp
			 *  certUsageSSLClient = 0 (which is the mode in which this function is used here)
			 */
			functions.CERT_GetCertChainFromCert = libs.nssLib.declare("CERT_GetCertChainFromCert",
					  ctypes.default_abi,
					  types.CERTCertList.ptr,
					  types.CERTCertificate.ptr,
					  ctypes.int64_t,
					  ctypes.int);
		 
			/*
			 * See http://zenit.senecac.on.ca/wiki/dxr/source.cgi/mozilla/security/nss/lib/certdb/certdb.c
			 * and http://zenit.senecac.on.ca/wiki/dxr/source.cgi/mozilla/security/manager/ssl/src/nsNSSCertificate.cpp
			 */
			functions.CERT_DestroyCertList = libs.nssLib.declare("CERT_DestroyCertList",
					  ctypes.default_abi,
					  ctypes.void_t,
					  types.CERTCertList.ptr);

		};
		
		/**
		 * Do the necessary initializations so CBCertificateChainFetcher can be used to download certificate chains
		 * 
		 * @param libPaths The container that holds the paths of the native libraries
		 * @param osIsWin A Flag indicating if Crossbear is currently executed on a Windows OS
		 */
		Crossbear.CBCertificateChainFetcher.prototype.init = function init(libPaths, osIsWin) {
			try{
			
			// First define the handles to the native libraries
			self.libs = new Object();
			self.openFFLibraries(self.libs,libPaths);

			// Then define the c-types
			self.types = new Object();
			self.defineFFLibTypes(self.types, osIsWin);

			// Finally define the c-type-functions
			self.functions = new Object();
			self.defineFFlibFunctions(self.functions, self.types, self.libs);
			
			}catch(e){
				cbFrontend.displayTechnicalFailure("CBCertificateChainFetcher:init failed: "+e ,true);
			}
		};

		/**
		 * Convert an IP and a Port into a NetAddress-struct which resides in an explicitly allocated memory area.
		 * 
		 * Please note: Since the memory of the NetAddress has explicitly been allocated it needs to be freed using the freeNetAddress-function
		 * 
		 * @param ip The IP to add to the NetAddress
		 * @param port The Port to add to the NetAddress
		 * @returns The NetAddress-struct-representation of the IP and the Port.
		 */
		Crossbear.CBCertificateChainFetcher.prototype.getNetAddress = function getNetAddress(ip, port) {

			// Allocate a buffer for 1024 bits and initialize it with zero
			var netAddressBuffer = self.functions.PR_Calloc(1, 1024);
			if (netAddressBuffer == 0) {
				cbFrontend.displayTechnicalFailure("PR_Calloc failed: " + self.functions.PR_GetError() ,true);
				return null;
			}

			// Cast the buffer into a "someStruct" (since NetAddress is not explicitly defined)
			var netAddress = ctypes.cast(netAddressBuffer, self.types.someStruct.ptr);

			// Set the Port-field of the NetAddress
			var success = self.functions.PR_InitializeNetAddr(0, port, netAddress);
			if (success != self.types.PR_SUCCESS) {
				
				//Free all allocated memory
				self.functions.PR_Free(netAddressBuffer);
				cbFrontend.displayTechnicalFailure("PR_InitializeNetAddr failed: " + self.functions.PR_GetError() ,true);
				return null;
			}

			// Set the IP-field of the NetAddress (works for IPv4 and IPv6 addresses)
			success = self.functions.PR_StringToNetAddr(ip, netAddress);
			if (success != self.types.PR_SUCCESS) {
				
				//Free all allocated memory
				self.functions.PR_Free(netAddressBuffer);
				cbFrontend.displayTechnicalFailure("PR_StringToNetAddr failed: " + self.functions.PR_GetError() ,true);
				return null;
			}

			return netAddress;
		};

		/**
		 * Free the memory of an explicitly allocated NetAddress-struct
		 * 
		 * @param netAddress A Pointer to the NetAddress-struct that should bee freed
		 */
		Crossbear.CBCertificateChainFetcher.prototype.freeNetAddress = function freeNetAddress(netAddress) {
			var netAddressBuffer = ctypes.cast(netAddress, ctypes.voidptr_t);
			self.functions.PR_Free(netAddressBuffer);
		};

		/**
		 * Convert a socket into a SSL-socket and enable SNI or - in case compatibilityMode==true - "SSLv2Hello"-Protocol-legacy support
		 * 
		 * @param socket The socket to convert
		 * @param host The name of the Host to contact in case the server supports SNI
		 * @param compatibilityMode If set to "true" TLS will be disabled and support for the "SSLv2Hello"-Protocol will be enabled. Some older servers require this option
		 * @returns The converted socket if no error occurred else false.
		 */
		Crossbear.CBCertificateChainFetcher.prototype.prepareSocketForSSL = function prepareSocketForSSL(socket, host, compatibilityMode) {

			// Convert the socket into a SSL-socket
			var sock = self.functions.SSL_ImportFD(null, socket);
			if (sock == 0) {
				cbFrontend.displayTechnicalFailure("SSL_ImportFD failed: " + self.functions.PR_GetError() ,true);
				return null;
			}

			// Check if the connection should be made in legacy-mode
			if (!compatibilityMode) {

				// If not: Enable SNI and set "host" as target-url
				var success = self.functions.SSL_SetURL(sock, host);
				if (success != self.types.PR_SUCCESS) {
					cbFrontend.displayTechnicalFailure("SSL_SetURL failed: " + self.functions.PR_GetError() ,true);
					return null;
				}

			} else {

				//If yes: disable TLS ...
				var success = self.functions.SSL_OptionSet(sock, self.types.SSL_ENABLE_TLS, self.types.PR_FALSE);
				if (success != self.types.SECSuccess) {
					cbFrontend.displayTechnicalFailure("SSL_OptionSet for SSL_ENABLE_TLS failed: " + self.functions.PR_GetError() ,true);
					return null;
				}

				// ... and enable SSLv3 (implicitly enables the "SSLv2Hello"-Protocol)
				success = self.functions.SSL_OptionSet(sock, self.types.SSL_ENABLE_SSL3, self.types.PR_TRUE);
				if (success != self.types.SECSuccess) {
					cbFrontend.displayTechnicalFailure("SSL_OptionSet for SSL_ENABLE_SSL3 failed: " + self.functions.PR_GetError() ,true);
					return null;
				}
			}

			return sock;
		};

		/**
		 * Certificate authentication callback function that accepts all certificates
		 * 
		 * @param arg A pointer to the handle of the certificate database to be used in validating the certificate's signature
		 * @param fd A pointer to the file descriptor for the SSL socket
		 * @param checksig PR_TRUE means signatures are to be checked and the certificate chain is to be validated. PR_FALSE means they are not to be checked
		 * @param isServer PR_TRUE means the callback function should evaluate the certificate as a server does, treating the remote end is a client. PR_FALSE means the callback function should evaluate the certificate as a client does, treating the remote end as a server
		 * @returns PR_SUCCESS (i.e. accept)
		 */
		Crossbear.CBCertificateChainFetcher.prototype.acceptAllCerts = function acceptAllCerts(arg, fd, checksig, isServer) {
			return self.types.PR_SUCCESS;
		};

		/**
		 * Perform a SSL-Handshake and get the peer's certificate.
		 * 
		 * @param socket The SSL-socket connected to the peer from which the certificate should be obtained
		 * @returns A CERTCertificate* pointing to the peer's certificate. If something went wrong while performing the handshake either null or a numeric error code is returned.
		 */
		Crossbear.CBCertificateChainFetcher.prototype.getPeerCertificate = function getPeerCertificate(socket) {

			// Set the certificate authentication callback function to "acceptAllCerts" so the handshake will not fail no matter what certificate the server is using
			var certAuthCallback = self.types.SSL_AuthCertificate(self.acceptAllCerts);
			var success = self.functions.SSL_AuthCertificateHook(socket, certAuthCallback, null);
			if (success != self.types.PR_SUCCESS) {
				cbFrontend.displayTechnicalFailure("SSL_AuthCertificateHook failed: " + self.functions.PR_GetError() ,true);
				return null;
			}

			// Reset the handshake state so a clean SSL-handshake can be performed
			success = self.functions.SSL_ResetHandshake(socket, self.types.PR_FALSE);
			if (success != self.types.PR_SUCCESS) {
				cbFrontend.displayTechnicalFailure("SSL_ResetHandshake failed: " + self.functions.PR_GetError() ,true);
				return null;
			}

			// Perform a clean SSL-handshake
			success = self.functions.SSL_ForceHandshakeWithTimeout(socket, self.functions.PR_SecondsToInterval(10));
			if (success != self.types.PR_SUCCESS) {
				/*
				 * An error code of SSL_ERROR_RX_RECORD_TOO_LONG seems to indicate that the host doesn't use SSL. This could be used to warn the user since the host is assumed to use SSL.
				 * An error code of SSL_ERROR_ILLEGAL_PARAMETER_ALERT indicates that the host doesn't support TLS and must be accessed using the "SSLv2Hello"-Protocol (i.e. using the legacy-mode). This will be done automatically when using the getCertificateChainFromServerFB-function.
				 */ 
				var errorCode = self.functions.PR_GetError();
				cbFrontend.displayTechnicalFailure("SSL_ForceHandshakeWithTimeout failed: " + errorCode  ,false);
				return errorCode;
			}

			// Get the peer's certificate ...
			var cert = self.functions.SSL_PeerCertificate(socket);
			if (cert == 0) {
				var errorCode = self.functions.PR_GetError();
				cbFrontend.displayTechnicalFailure("SSL_PeerCertificate failed: " + errorCode ,false);
				return errorCode;
			}

			// ... and return a pointer to it.
			return cert;
		};

		/**
		 * Get a pointer to the first element of a certificate chain.
		 * 
		 * This function is implemented according to the original defines of the Firefox sourcecode:
		 * #define CERT_LIST_HEAD(l) ((CERTCertListNode *)PR_LIST_HEAD(&l->list))
		 * #define PR_LIST_HEAD(_l) (_l)->next
		 * 
		 * @param certChain A pointer to the certificate chain to the first element from 
		 * @returns A CERTCertListNode* pointing to the first element of the certificate chain
		 */
		Crossbear.CBCertificateChainFetcher.prototype.CERT_LIST_HEAD = function CERT_LIST_HEAD(certChain) {
			return ctypes.cast(certChain.contents.list.next, self.types.CERTCertListNode.ptr);
		};

		/**
		 * Check whether a given certificate is the last element of a certificate chain.
		 * 
		 * This function is implemented according to the original defines of the Firefox sourcecode:
		 * #define CERT_LIST_END(n,l) (((void *)n) == ((void *)&l->list))
		 * 
		 * @param node The node in question
		 * @param certChain The certificate chain
		 * @returns True if the node IS the last element in the chain else false
		 */
		Crossbear.CBCertificateChainFetcher.prototype.CERT_LIST_END = function CERT_LIST_END(node, certChain) {

			// Cast both pointers into void-pointers so their string-representation will be the same
			var rhs = ctypes.cast(certChain.contents.list.address(), ctypes.voidptr_t);
			var lhs = ctypes.cast(node, ctypes.voidptr_t);

			// Compare the pointers by comparing their string representations (officially recommended method)
			return lhs.toString() == rhs.toString();
		};

		/**
		 * Get the successor of a node in a certificate chain.
		 * 
		 * This function is implemented according to the original defines of the Firefox sourcecode:
		 * #define CERT_LIST_NEXT(n) ((CERTCertListNode *)n->links.next)
		 * 
		 * @param node The node for which the successor should be returned
		 * @returns A CERTCertListNode * pointing to the successor of "node"
		 */
		Crossbear.CBCertificateChainFetcher.prototype.CERT_LIST_NEXT = function CERT_LIST_NEXT(node) {

			return ctypes.cast(node.contents.links.next, self.types.CERTCertListNode.ptr);
		};

		/**
		 * Get the certificate chain that belongs to a certificate
		 * 
		 * @param cert A CERTCertificate* pointing to the certificate for which the chain should be obtained
		 * @returns An array of DER-encoded certificates of which the first element is "cert" and the others are "cert"'s chain or null if something went wrong
		 */
		Crossbear.CBCertificateChainFetcher.prototype.getCertificateChainForCert = function getCertificateChainForCert(cert) {

			// Use CERT_GetCertChainFromCert to obtain the certificate's chain
			var certChain = self.functions.CERT_GetCertChainFromCert(cert, self.functions.PR_Now(), 0);
			if (certChain == 0) {
				cbFrontend.displayTechnicalFailure("CERT_GetCertChainFromCert failed: " + self.functions.PR_GetError() ,true);
				return null;
			}

			// Iterate through the chain and copy all of its members to a new array. This needs to be done since the original data will be freed
			var certRawArray = [];
			for ( var node = self.CERT_LIST_HEAD(certChain); !self.CERT_LIST_END(node, certChain); node = self.CERT_LIST_NEXT(node)) {
				//alert(node.contents.cert.contents.subjectName.readString());
				
				// Get the DER-encoded data of the certificate as Javascript array
				var asArray = ctypes.cast(node.contents.cert.contents.derCert.data, ctypes.ArrayType(ctypes.unsigned_char, node.contents.cert.contents.derCert.len).ptr).contents;

				// Quick & Dirty binary copy of the DER-encoded certificate into the output array :D
				certRawArray.push(Crossbear.uint8ArrayToJSArray(Crossbear.jsArrayToUint8Array(asArray)));
			}

			// Free the certificate chain that CERT_GetCertChainFromCert generated
			self.functions.CERT_DestroyCertList(certChain);

			// Return the array of DER-encoded certificates representing "cert"'s certificate chain
			return certRawArray;
		};

		/**
		 * Contact a server and get its certificate chain.
		 * 
		 * @param ip The IP of the server
		 * @param ipVersion The IP-version of the server's IP-address
		 * @param port The port of the server
		 * @param host The Hostname of the server (required for SNI)
		 * @param compatibilityMode If set to "true" TLS will be disabled and support for the "SSLv2Hello"-Protocol will be enabled. Some older servers require this option
		 * @returns An array of DER-encoded certificates of which the first element is the server's certificate and the others are its chain. If something went wrong either null or a numeric error code is returned.
		 */
		Crossbear.CBCertificateChainFetcher.prototype.getCertificateChainFromServer = function getCertificateChainFromServer(ip, ipVersion, port, host, compatibilityMode) {

			// Convert the server's IP and port into a NetAddress
			var netAddress = self.getNetAddress(ip, port);
			if (netAddress == null) {
				return null;
			}

			// Open a TCP-connection to the server (using the correct IP-version)
			var socket = self.functions.PR_OpenTCPSocket((ipVersion == 6) ? self.types.PR_AF_INET6 : self.types.PR_AF_INET);
			if (socket == 0) {
				
				// Free all allocated memory
				self.freeNetAddress(netAddress);
				cbFrontend.displayTechnicalFailure("PR_OpenTCPSocket failed: " + self.functions.PR_GetError() ,true);
				return null;
			}

			// Prepare the connection for SSL (and if applicable SNI)
			socket = self.prepareSocketForSSL(socket, host, compatibilityMode);
			if (socket == null) {
				
				// Free all allocated memory
				self.freeNetAddress(netAddress);
				return null;
			}

			// Try to connect to the server
			var success = self.functions.PR_Connect(socket, netAddress, self.functions.PR_SecondsToInterval(20));
			if (success != self.types.PR_SUCCESS) {
				
				// Free all allocated memory
				self.freeNetAddress(netAddress);
				cbFrontend.displayTechnicalFailure("PR_Connect failed: " + self.functions.PR_GetError() ,false);
				return null;
			}

			// Get the server's certificate
			var peerCertificate = self.getPeerCertificate(socket);
			if(peerCertificate == null || ( typeof peerCertificate == "number")) {
				
				// Free all allocated memory
				self.freeNetAddress(netAddress);
				return peerCertificate;
			}

			// Get the certificate chain for the server's certificate
			var certChain = self.getCertificateChainForCert(peerCertificate);
			if (certChain == null) {

				// Free all allocated memory
				self.freeNetAddress(netAddress);
				self.functions.CERT_DestroyCertificate(peerCertificate);

				return null;
			}

			// Free the memory of the server's certificate
			self.functions.CERT_DestroyCertificate(peerCertificate);

			// Shutdown the connection to the server
			success = self.functions.PR_Shutdown(socket, self.types.PR_SHUTDOWN_BOTH);
			if (success != self.types.PR_SUCCESS) {

				// Free all allocated memory
				self.freeNetAddress(netAddress);
				cbFrontend.displayTechnicalFailure("PR_Shutdown failed: " + self.functions.PR_GetError() ,true);
				return null;
			}

			// Close the connection to the server
			var success = self.functions.PR_Close(socket);
			if (success != self.types.PR_SUCCESS) {

				// Free all allocated memory
				self.freeNetAddress(netAddress);
				cbFrontend.displayTechnicalFailure("PR_Close failed: " + self.functions.PR_GetError() ,true);
				return null;
			}

			// Free all allocated memory
			self.freeNetAddress(netAddress);

			// Return the array of DER-encoded certificates representing the server's certificate chain
			return certChain;
		};

		/**
		 * Contact a server and get its certificate chain. First try using TLS/SSLv3 and if that failed fall back to legacy-mode
		 * 
		 * @param ip The IP of the server
		 * @param ipVersion The IP-version of the server's IP-address
		 * @param port The port of the server
		 * @param host The Hostname of the server (required for SNI)
		 * @returns An array of DER-encoded certificates of which the first element is the server's certificate and the others are its chain. If something went wrong null will be returned
		 */
		Crossbear.CBCertificateChainFetcher.prototype.getCertificateChainFromServerFB = function getCertificateChainFromServer(ip, ipVersion , port, host) {

			// Try to get the server's certificate using TLS/SSLV3 with SNI enabled
			var certChain = self.getCertificateChainFromServer(ip, ipVersion, port, host, false);
			if ((typeof certChain == "number") && certChain == self.types.SSL_ERROR_ILLEGAL_PARAMETER_ALERT) {

				// If that failed because of the fact that the server doesn't support TLS/SSLV3 try again with legacy-mode enabled
				certChain = self.getCertificateChainFromServer(ip, ipVersion, port, host, true);

			}
			
			// Return the certificate chain if it could be obtained or null if that was not possible
			return (typeof certChain == "number")?null:certChain;
		};
	}
};