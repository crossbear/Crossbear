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
 * Crossbear's Protector-functionality is implemented by the use of a "http-on-examine-response"-Event-Observer. To be precise a "http-on-examine-response"-Event-Handler will be active as soon as Crossbear's Protector is initialized. This Handler checks the
 * certificate of each and every HTTPS-connection. The Protector will always monitor the connections to the Crossbear-Server. All others will only be monitored if the protector is set to "active".
 * 
 * If a certificate has never been seen for the connection's domain, the certificate is sent to the Crossbear server for validation. The result will then be displayed to the user who has to decide whether he/she wan't to trust the certificate for
 * that domain or not. If the certificate has already been seen for that domain before, the user's trust decision is read from the local cache and applied again. Although the validation is requested here, it is done within the CBProtector.
 * 
 * 
 * Please note: This object implements the nsIObserver-Interface since that is necessary in order to observe Events.
 * 
 * @param cbFrontend The cbFrontend-class that will be used to display information/errors to the user
 * 
 * @author Thomas Riedmaier
 */
Crossbear.CBEventObserver = function (cbFrontend) {
	this.cbFrontend = cbFrontend;
	
	// Flag stating whether the Protector should check all connections or only those to the Crossbear-Server
	this.checkCBServerOnly = true;
	
	// "this" does not always point to THIS object (especially in callback functions). Therefore I use the "self" variable to hold a handle on THIS object
	var self = this;

	// Load the Firefox Component required to work with event listeners
	var observerService = Components.classes["@mozilla.org/observer-service;1"].getService(Components.interfaces.nsIObserverService);
	
	// Mark this object as event-listener for the "http-on-examine-response"-event. This allows Crossbear to intercept page loads
	observerService.addObserver(self, "http-on-examine-response", false);
	
	// Mark this object as event-listener for the "quit-application-requested"-event. This allows Crossbear to perform a clean shutdown when the user closes firefox
	observerService.addObserver(self, "quit-application-requested", false);
	
	// Mark this object as event-listener for the "private-browsing"-event. This allows Crossbear to deactivate itself when the user enters the private browsing mode
	observerService.addObserver(self, "private-browsing", false);

	// Initialize the member function references for the class prototype (like this it's only done once and not every time a instance of this object is created)
	if (typeof (_crossbear_eventobserver_prototype_called) == 'undefined') {
		_crossbear_eventobserver_prototype_called = true;
		
		
		
		/**
		 * (De-)Activate the Protector. Activating the Protector will cause all connections to be checked. Deactivating the Protector will limit the connection-checking to connections to the Crossbear-server
		 */
		Crossbear.CBEventObserver.prototype.setProtectorActivity = function setProtectorActivity(active) {
			self.checkCBServerOnly = !active;
		};

		/**
		 * The observe-function as specified by the nsIObserver-Interface. It will be used to observe 'quit-application-requested'-events and 'http-on-examine-response'-events. The former triggers a clean shutdown of the Crossbear system while the
		 * latter will cause the connection's certificate to be checked. For more details read the description of this class.
		 * 
		 * @param aSubject In general reflects the object whose change or action is being observed(e.g. the http-connection).
		 * @param aTopic Indicates the specific change or action(e.g. 'quit-application-requested' or 'http-on-examine-response').
		 * @param aData An optional parameter or other auxiliary data further describing the change or action(not used).
		 */
		Crossbear.CBEventObserver.prototype.observe = function observe(aSubject, aTopic, aData) {
			
			// In case the user wants to shutdown Firefox
			if (aTopic == 'quit-application-requested') {

				 // ... Perform a clean shutdown of Crossbear
				cbFrontend.shutdown(false);

			// In case the user enters or leaves the "private-browsing" mode ...
			} else if (aTopic == 'private-browsing') {
				if (aData == "enter") { 
					
					// ... notify the user that he will no longer be protected by Crossbear
					cbFrontend.warnUserAboutBeingUnderAttack(new XML("<p>You entered the private-browsing mode. Crossbear will NOT protect you while you are using that mode!</p>"),0);
					
					// ... deactivate the Protector, and
					cbFrontend.deactivateProtector(false);
					
					// ... deactivate the Hunter
					cbFrontend.deactivateHunter(false);
					
				} else if (aData == "exit") { 

					// ... activate the Protector, and
					cbFrontend.activateProtector();
					
					// ... activate the Hunter
					cbFrontend.activateHunter(false);

				}
				
			// In case a HTTP-Conection was made ...
			} else if (aTopic == 'http-on-examine-response') {
				
				// ... get the URL that was requested and the one that the server actually sent
				var origUrl = aSubject.QueryInterface(Components.interfaces.nsIChannel).originalURI.spec;
				var url = aSubject.QueryInterface(Components.interfaces.nsIChannel).URI.spec;
				
				// Try to extract the Hostname from the url (will fail in case the connection itself failed)
				try{
					var host = Crossbear.extractHostname(url).split(":")[0];
				} catch(e){
					//In case the connection failed do nothing
					return;
				}
				
				// Check if the originally requested URL was a HTTPs resource
				var origUrlIsHttps = origUrl.match(/^https:\/\/.*/i);
				
				// Check if the URL to which the browser was redirected is a HTTPS resource
				var urlIsHttps = url.match(/^https:\/\/.*/i);

				// ... if not, Crossbear has nothing to do with this request
				if (!origUrlIsHttps && !urlIsHttps) {
					return;
				}
				
				// If the user requested a HTTPS-resource but was redirected to an unsafe HTTP-resource
				if(origUrlIsHttps && !urlIsHttps){
					
					// Rise a warning! (except when the user disabled the protector or the warning)
					if(!self.checkCBServerOnly && cbFrontend.getUserPref("protector.showRedirectWarning", "bool")){
						cbFrontend.warnUserAboutBeingUnderAttack(new XML("<p>You requested a SSL-secured resource but the server redirected you to an unsafe resource. You might be under attack!</p>"),0);
					}
					return;
				}
				
				// Firefox allows connections to HTTPS-pages using their IPv4-addresses. Crossbear does currently not support this.
				if(host.match(Crossbear.ipv4Regex)){
					
					// If the IP belongs to a local IP or if the user deactivated the protector -> allow it anyways
					if(host.match(Crossbear.privateIPRegex) || self.checkCBServerOnly){
						return;
						
					// If not warn the user and cancel the connection
					} else{
						cbFrontend.warnUserAboutBeingUnderAttack(new XML('<p xmlns:html="http://www.w3.org/1999/xhtml">You tried to access a HTTPS-page using its IP-Address. This is strongly disencouraged and currently not supported by Crossbear.<html:br /><html:br /> If you want to go on you have to disable the Crossbear-Protector!</p>'),0);
						aSubject.QueryInterface(Components.interfaces.nsIChannel).cancel(Components.results.NS_BINDING_SUCCEEDED);
						return;
					}
					
				}

				// Try to extract the server's certificate
				var serverCert;
				try {
					serverCert = aSubject.QueryInterface(Components.interfaces.nsIChannel).securityInfo.QueryInterface(Components.interfaces.nsISSLStatusProvider).SSLStatus.QueryInterface(Components.interfaces.nsISSLStatus).serverCert;
				} catch (e) {
					// The server didn't send any certificate. Since this is very suspicious -> warn the user!
					cbFrontend.warnUserAboutBeingUnderAttack(new XML("<p>You requested a SSL-secured resource but the server didn't send any certificate! You might be under an attack!</p>"),5);
					cbFrontend.displayTechnicalFailure("CBEventObserver:observe: could not extract server certificate for "+host, false);
					return;
				}

				// Get the Address of the server that sent the certificate in the format "IP|Port"
				var remoteAddress = aSubject.QueryInterface(Components.interfaces.nsIHttpChannelInternal).remoteAddress +"|"+aSubject.QueryInterface(Components.interfaces.nsIHttpChannelInternal).remotePort;
				
				// Get the certificate chain that the server is using
				var serverCertChain = Crossbear.getCertChainBytes(serverCert);
				
				// Generate the SHA256-Hash for the server certificate (this is its identifier in the local cache)
				var serverCertHash = Crypto.SHA256(serverCertChain[0], {});

				/*
				 * Check if the certificate that the connection uses should be trusted or not. If that is not yet known, contact the Crossbear server and request a certificate verification. As soon as the server replied, display that reply to the
				 * user. Finally: apply the user's trust decision.
				 */
				cbFrontend.cbprotector.getAndApplyTrustDecision(aSubject.QueryInterface(Components.interfaces.nsIChannel), serverCertChain, serverCertHash, host+"|"+remoteAddress);
			}
		};
	}

};
