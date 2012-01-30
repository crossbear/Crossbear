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
 * This is the dialog that will display the rating and judgments that were sent by the Crossbear server in response to a CertVerifyRequest. The user will be given the choice whether or not he/she want's to trust the certificate that was verified by
 * Crossbear. A Timeout while connecting to the Crossbear server is handled by displaying the two buttons two the user. The first one is a "Retry"-button while the second one is a "Deactivate Protector"-button.
 * 
 * Each dialog is equipped with a periodically executed function that puts the focus on the oldest dialog window (if there are more than one). This is necessary since occasionally windows open BEHIND the main Firefox window. Additionally, the
 * constant focusing of the oldest window reduces the user's confusion when a lot of dialogs pop up.
 * 
 * The same periodically executed function that focuses the oldest window also checks if the certificate/domain-combination of the dialog has been inserted into the local cache in the meantime. The effect of this is that in case duplicate windows are
 * opened the user does not have to make duplicate decissions.
 * 
 * If the user activated the option to automatically trust a certificate when its rating is more than X then no UnknownCerDlg-window will be shown.
 * 
 */

// Timer that periodically triggers the execution of the "checkIfCertIsInCache"-function.
var checkIfCertIsInCacheTimer = null;

/**
 * Bring the oldest (i.e. the first opened) UnknownCertDlg-window to the front and put the focus on it. This is necessary since sometimes UnknownCertDlg-windows are opened BEHIND the main Firefox window. Furthermore continuous focusing of the oldest
 * window reduces the user's confusion about dozents of windows popping up in the same position (since he/she will always see the oldest one).
 * 
 * Please note: There is a known Bug when this function is executed on a Ubuntu-system: The UnknownCertDlg that has been brought to front is focused but does not respond to mouse-clicks. Current work-around: Choose the desired option by keyboard
 */
function bringToFront() {

	try {

		// Get a handle to Firefox's WindowMediator
		var wm = Components.classes["@mozilla.org/appshell/window-mediator;1"].getService(Components.interfaces.nsIWindowMediator);

		// If there currently is a WarnUserDlg then don't unfocus it! (just return)
		if (wm.getMostRecentWindow("WarnUserDlg"))
			return;

		// Focus the newest UnknownCertDlg
		//wm.getMostRecentWindow("UnknownCertDlg").focus();

		// Focus the oldest UnknownCertDlg
		var windowEnum = wm.getEnumerator("UnknownCertDlg");
		windowEnum.getNext().focus();

	} catch (e) {
		window.arguments[0].inn.cbFrontend.displayTechnicalFailure("UnknownCertDlg:bringToFront: could not bring a window to front.", false);
	}
}

/**
 * This function checks if the dialog's Certificate/domain-combination was inserted into the CBCertificateCache. If it was then the window is closed. If not the bringToFront-function is called.
 * 
 * @param forceWindowClose If true then the window will be closed no matter whether the Certificate/domain-combination was inserted in the CBCertificateCache. This is useful e.g. when the system is about to shut down or when the protector was deactivated.
 */
function checkIfCertIsInCache(forceWindowClose) {

	// Ask the cache if the host's certificate should be trusted for its domain
	var cacheStatus = window.arguments[0].inn.cbFrontend.cbcertificatecache.checkValidity(window.arguments[0].inn.certHash, window.arguments[0].inn.host.split("|")[0],window.arguments[0].inn.cbFrontend.cbeventobserver.checkCBServerOnly);

	// If the cache can answer that question or if the window must be closed ...
	if (cacheStatus != CBCertificateCacheReturnTypes.NOT_IN_CACHE || forceWindowClose) {
		
		// ... close it.
		window.close();
		return;
	}

	// If the question can't be answered then set the focus on the oldest UnknownCertDlg. The user is then forced to answer the trust-question for the oldest window's certificate.
	bringToFront();
}

/**
 * Initialization function (called once when the dialog is about to display). This function sets all GUI-elements according to the window.arguments[0].inn-parameters and creates a timer that will periodically execute the checkIfCertIsInCache-function.
 */
function onLoad() {

	// Display the "Trust" & "Don't Trust" buttons or the "Retry" & "Deactivate Protector" buttons depending on whether a timeout occurred or not
	document.getElementById('buttonBox').hidden = window.arguments[0].inn.wasTimeout;
	document.getElementById('timeoutButtonBox').hidden = !window.arguments[0].inn.wasTimeout;

	// Put the rating in the dialog's "server-reply"-box
	document.getElementById('serverReplyRating').value = window.arguments[0].inn.rating;

	// Convert the judgment from Text-only to HTML
	var contentHTML = window.arguments[0].inn.judgment.replace(/\n/g,"<html:br />").replace(/<crit>/g,"<html:font color=\"red\"><html:b>").replace(/<\/crit>/g,"</html:b></html:font>");
	
	// Put the judgment in the dialog's "server-reply"-box
	var srd = document.getElementById("serverReplyDiv");
	srd.innerHTML ="<p xmlns=\"http://www.mozilla.org/keymaster/gatekeeper/there.is.only.xul\" style=\"word-wrap: break-word;\">"+contentHTML+"</p>";

	// If the box became too big: Limit its width
	if(srd.offsetWidth>415){
		srd.innerHTML ="<p xmlns=\"http://www.mozilla.org/keymaster/gatekeeper/there.is.only.xul\" width=\"415px\" style=\"word-wrap: break-word;\">"+contentHTML+"</p>";
	}

	// Color the rating based on whether it is below or above the user's ratingToTrustAutomatically-value
	if (window.arguments[0].inn.rating > window.arguments[0].inn.ratingToTrustAutomatically) {

		// If it's above: color the rating green
		document.getElementById('serverReplyRating').style.color = "#22B14C";

	} else {
		// If it's below: color the rating red
		document.getElementById('serverReplyRating').style.color = "#FF0000";
	}

	// Resize the window so it is big enough to display its content (especially important on linux-systems)
	window.sizeToContent();

	// Set a Timer to periodically call the checkIfCertIsInCache-function ( So this dialog will close as soon as there is information about the certificate's trust in the local cache and the oldest UnknownCertDlg will be focused)
	checkIfCertIsInCacheTimer = window.setInterval(function() {
		checkIfCertIsInCache(!window.arguments[0].inn.cbFrontend.cbeventobserver.protectorIsActive);
	}, 500);

}

/**
 * In case the server could not be contacted and the user chose to deactivate the Protector this function will be called
 */
function deactivateProtector() {

	// Call the function that will actually deactivate the Protector
	window.arguments[0].inn.cbFrontend.deactivateProtector(true);

	// Stop the timer that calls the contactCBServer-function ...
	clearInterval(checkIfCertIsInCacheTimer);

	// ... and close the dialog.
	window.close();

}

/**
 * In case the server could not be contacted and the user chose to try to contact the Crossbear server again, this function will be called
 */
function retry() {

	// Contact the Crossbear server again
	window.arguments[0].inn.cbFrontend.cbprotector.requestVerification(window.arguments[0].inn.certChain, window.arguments[0].inn.certHash, window.arguments[0].inn.host);

	// Stop the timer that calls the contactCBServer-function ...
	clearInterval(checkIfCertIsInCacheTimer);

	// ... and close the dialog.
	window.close();
}

/**
 * This is the function that will add the host's "certificate"/"domain"-combination to the local cache.
 * 
 * @param trust "1" if the user want's the certificate to be trusted, else "0"
 * @returns true (So the dialog will close)
 */
function setTrust(trust) {

	// Add a new entry in the CBCertificateCache for the host's certificate and domain according to the user's choice of trust and his/hers defaultCacheValidity
	window.arguments[0].inn.cbFrontend.cbprotector.addCacheEntryDefaultValidity(window.arguments[0].inn.certHash, window.arguments[0].inn.host.split("|")[0], trust);

	// Stop the timer that calls the contactCBServer-function ...
	clearInterval(checkIfCertIsInCacheTimer);

	// Return true so the dialog will close
	return true;
}