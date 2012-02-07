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
 * certificate of each and every HTTPS-connection. The Protector will always monitor the connections to the Crossbear-Server. All others will only be monitored if the protector is set as "active".
 * 
 * If a certificate has never been seen for the connection's domain, the certificate is sent to the Crossbear server for validation. The result will then be displayed to the user who has to decide whether he/she wan't to trust the certificate for
 * that domain or not. If the certificate has already been seen for that domain before, the user's trust decision is read from the local cache and applied again.
 * 
 * After the Event-Handler returned, the page will be displayed in case the Event-Handler didn't explicitly cancel the page load process. Since Crossbear must never display data of pages that use a untrusted certificate, the
 * "http-on-examine-response"-Event-Handler mustn't return before the user made a decision about the certificate. This means that there has to be some kind of "wait-for-the-server-to-reply-and-the-user-to-choose"-loop in the Event-Handler. The
 * problem with this is that a loop like that will freeze Firefox if it is implemented naively. Therefore, the CBEvent-Observer calls currentThread.processNextEvent() until a reply from the server is received. This permits Firefox to continue working
 * normally (e.g. to download data from the Crossbear server) without returning from the Event-Handler.
 * 
 * Please note: This object implements the nsIObserver-Interface since that is necessary in order to observe Events.
 * 
 * @param cbFrontend The cbFrontend-class that will be used to display information/errors to the user
 * 
 * @author Thomas Riedmaier
 */
function CBEventObserver(cbFrontend) {
	this.cbFrontend = cbFrontend;
	
	// Flag indicating if the Protector is currently active
	this.protectorIsActive = false;
	
	// Flag stating whether the Protector should check all connections or only those to the Crossbear-Server
	this.checkCBServerOnly = true;
	
	// "this" does not always point to THIS object (especially in callback functions). Therefore I use the "self" variable to hold a handle on THIS object
	var self = this;

	// Load the Firefox Component required to work with event listeners
	var observerService = Components.classes["@mozilla.org/observer-service;1"].getService(Components.interfaces.nsIObserverService);
	
	// Mark this object as event-listener for the "quit-application-requested"-event. This allows Crossbear to perform a clean shutdown when the user closes firefox
	observerService.addObserver(self, "quit-application-requested", false);

	// Initialize the member function references for the class prototype (like this it's only done once and not every time a instance of this object is created)
	if (typeof (_cbeventobserver_prototype_called) == 'undefined') {
		_cbeventobserver_prototype_called = true;
		
		/**
		 * Initialize the Protector
		 */
		CBEventObserver.prototype.initProtector = function initProtector() {
			
			// Check if the Protector is already active
			if(!self.protectorIsActive){
				
				// If not: initialize it (i.e. add this object as event-listener for the "http-on-examine-response"-event. This will allow Crossbear to inspect each and every page before it is displayed)
				observerService.addObserver(self, "http-on-examine-response", false);
			}
			
			// Set the activity-flag to true
			self.protectorIsActive = true;
		};
		
		/**
		 * Shut the Protector down
		 */
		CBEventObserver.prototype.shutdownProtector = function shutdownProtector() {
			
			// Check if the Protector is active
			if(self.protectorIsActive){
				
				//If yes: shut it down (i.e. remove this object from the list of event-listeners for the "http-on-examine-response"-event)
				observerService.removeObserver(self, "http-on-examine-response");
			}
			
			// Set the activity-flag to false
			self.protectorIsActive = false;
		};
		
		
		
		/**
		 * (De-)Activate the Protector. Activating the Protector will cause all connections to be checked. Deactivating the Protector will limit the connection-checking to connections to the Crossbear-server
		 */
		CBEventObserver.prototype.setProtectorActivity = function setProtectorActivity(active) {
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
		CBEventObserver.prototype.observe = function observe(aSubject, aTopic, aData) {
			
			//SUGG: Implement a event observer for the "private-browsing" and disable the Protector every time the user switches to private browsing mode
			
			// In case the user wants to shutdown Firefox
			if (aTopic == 'quit-application-requested') {

				 // ... Perform a clean shutdown of Crossbear
				cbFrontend.shutdown(false);

			// In case a HTTP-Conection was made ...
			} else if (aTopic == 'http-on-examine-response') {
				
				// ... get the URL that was requested and the one that the server actually sent
				var origUrl = aSubject.QueryInterface(Components.interfaces.nsIChannel).originalURI.spec;
				var url = aSubject.QueryInterface(Components.interfaces.nsIChannel).URI.spec;
				
				// Try to extract the Hostname from the url (will fail in case the connection itself failed)
				try{
					var host = url.getHostname();
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
				
				// If the user requested a HTTPS-ressource but was redirected to an unsafe HTTP-resource -> Rise a warning!
				if(origUrlIsHttps && !urlIsHttps){
					cbFrontend.warnUserAboutBeingUnderAttack("You requested a SSL-secured resource but the server redirected you to an unsafe resource. You might be under attack!",0);
					return;
				}
				
				// Firefox allows connections to HTTPS-pages using their IPv4-addresses. Crossbear does currently not support this.
				var hostNoPort = host.split(":")[0];
				if(hostNoPort.match(ipv4Regex)){
					
					// If the IP belongs to a local IP-> allow it anyways
					if(hostNoPort.match(privateIPRegex)){
						return;
						
					// If not warn the user and cancel the connection
					} else{
						cbFrontend.warnUserAboutBeingUnderAttack("You tried to access a HTTPS-page using its IP-Address. This is strongly disencouraged and currently not supported by Crossbear.<html:br /><html:br /> If you want to go on you have to disable the Crossbear-Protector!",0);
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
					cbFrontend.warnUserAboutBeingUnderAttack("You requested a SSL-secured resource but the server didn't send any certificate! You might be under an attack!",5);
					cbFrontend.displayTechnicalFailure("CBEventObserver:observe: could not extract server certificate for "+host, false);
					return;
				}

				// Get the Address of the server that sent the certificate in the format "IP|Port"
				var remoteAddress = aSubject.QueryInterface(Components.interfaces.nsIHttpChannelInternal).remoteAddress +"|"+aSubject.QueryInterface(Components.interfaces.nsIHttpChannelInternal).remotePort;
				
				
				// Get the certificate chain that the server is using
				var cc = serverCert.getChain();
				var serverCertChain = [];
				for ( var i = 0; i < cc.length; i++) {

					var currentCert = cc.queryElementAt(i, Components.interfaces.nsIX509Cert);
					var currentCertBytesLength = {};
					serverCertChain.push(currentCert.getRawDER(currentCertBytesLength));
				}
				
				// Generate the SHA256-Hash for the server certificate (this is its identifier in the local cache)
				var serverCertHash = Crypto.SHA256(serverCertChain[0], {});

				// Check if the certificate has been seen for the domain. If yes: get the cached policy
				var cacheStatus = cbFrontend.cbtrustdecisioncache.checkValidity(serverCertHash, host, self.checkCBServerOnly);

				// Loop until the user decided whether to trust the host's certificate for this domain
				var verificationRequested = false;
				while (self.protectorIsActive) {

					// In case the user considers the connection's certificate valid for this domain -> Load the page.
					if (cacheStatus == CBTrustDecisionCacheReturnTypes.OK || cacheStatus == CBTrustDecisionCacheReturnTypes.CB_SERVER_OK) {
						return;
					}
					
					// In case the conection was targeted for the Crossbear Server but did not use the correct certificate: Warn the user and cancel the connection
					if (cacheStatus == CBTrustDecisionCacheReturnTypes.CB_SERVER_NOT_VALID) {
						cbFrontend.warnUserAboutBeingUnderAttack("The Crossbear server sent an unexpected certificate. It is VERY LIKELY that you are under attack by a Man-in-the-middle! Don't visit any security relevant pages (e.g. banks)!<html:br /><html:br /> You could do the research community a big favor by <html:a style=\"text-decoration:underline\" href=\"mailto:crossbear@pki.net.in.tum.de?subject=Observation%20of%20an%20invalid%20certificate%20for%20the%20Crossbear-Server&amp;body=Hey%20Crossbear-Team,%0D%0A%0D%0AI%20observed%20the%20following%20certificate%20chain%20for%20the%20Crossbear-Server("+remoteAddress+") on "+new Date().toGMTString() +"%0D%0A%0D%0A"+Crypto.util.bytesToBase64(getCertChainBytes(serverCert).implode())+"\">sending an email</html:a> to the Crossbear-Team.<html:br /><html:br />",5);
						aSubject.QueryInterface(Components.interfaces.nsIChannel).cancel(Components.results.NS_BINDING_SUCCEEDED);
						return;
					}
					
					// In case the user considers the connection's certificate INVALID for this domain -> Abort the page loading
					if (cacheStatus == CBTrustDecisionCacheReturnTypes.NOT_VALID) {
						cbFrontend.warnUserAboutBeingUnderAttack("You tried to access " + host + " with a certificate you don't trust. This attempt was canceled.",0);
						aSubject.QueryInterface(Components.interfaces.nsIChannel).cancel(Components.results.NS_BINDING_SUCCEEDED);
						return;
					}

					// If the cacheStatus is not "OK", "NOT_VALID", "CB_SERVER_OK", "CB_SERVER_NOT_VALID" or "NOT_IN_CACHE" then something is seriously going wrong -> Rise an exception
					if (cacheStatus != CBTrustDecisionCacheReturnTypes.NOT_IN_CACHE) {
						cbFrontend.displayTechnicalFailure("CBEventObserver:observe: TrustDecisionCache returned unknown value:"+cacheStatus, true);
						return;
					}
					
					// If the certificate/domain combination was not found in the local cache initially: Request the server to verify the certificate
					if(!verificationRequested){
						verificationRequested = true;
						cbFrontend.cbprotector.requestVerification(serverCertChain, serverCertHash, host+"|"+remoteAddress);
					}
					
					// Since this loop is not left until there is a trust decision about the certificate: Let the GUI-Thread process waiting events to avoid GUI-freezing
					var currentThread = Cc["@mozilla.org/thread-manager;1"].getService(Ci.nsIThreadManager).currentThread;
					currentThread.processNextEvent(true);

					// Check if the user decided whether or not to trust the certificate on the domain
					cacheStatus = cbFrontend.cbtrustdecisioncache.checkValidity(serverCertHash, host, self.checkCBServerOnly);
				}
			}
		};
	}

}
