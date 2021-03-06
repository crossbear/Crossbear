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
 * This is the dialog that will display the rating and judgments that were sent by the Crossbear server in response to a CertVerifyRequest. The user will be given the choice whether or not he/she want's to trust the certificate that was verified by
 * Crossbear. A Timeout while connecting to the Crossbear server is handled by displaying two buttons two the user. The first one is a "Retry"-button while the second one is a "Deactivate Protector"-button.
 * 
 * Each dialog is equipped with a periodically executed function that puts the focus on the oldest dialog window (if there are more than one). This is necessary since occasionally windows open BEHIND the main Firefox window. Additionally, the
 * constant focusing of the oldest window reduces the user's confusion when a lot of dialogs pop up.
 * 
 * The same periodically executed function that focuses the oldest window also checks if the user wants to shutdown the Crossbear protector. If that is the case then the dialog window is closed
 * 
 * If the user activated the option to automatically trust a certificate when its rating is more than X then no UnknownCerDlg-window will be shown.
 * 
 */

// Timer that periodically triggers the execution of the "bringToFrontAndCheckShutdown"-function.
var bringToFrontAndCheckShutdownTimer = null;

/**
 * Bring the oldest (i.e. the first opened) UnknownCertDlg-window to the front and put the focus on it. This is necessary since sometimes UnknownCertDlg-windows are opened BEHIND the main Firefox window. Furthermore continuous focusing of the oldest
 * window reduces the user's confusion about dozens of windows popping up in the same position (since he/she will always see the oldest one).
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
 * Periodically executed function that brings the oldest window to front and closes the dialog window if the protector should be shut down
 * 
 * @param forceWindowClose True if the protector should be shut down, false otherwise
 */
function bringToFrontAndCheckShutdown(forceWindowClose) {

	// Check if the window must be closed ...
	if (forceWindowClose) {

		// ... close it.
		window.close();
		return;
	}

	// Focus the oldest UnknownCertDlg-window
	bringToFront();
};

/**
 * Converts the textual representation of the judgment the Crossbear server sends into a XML representation
 * 
 * @param judgment The textual representation of the judgment (containing "\n"-characters and "<crit>"-tag)
 * @returns The XML representation of the judgment
 */
function convertJudgmentToXML(judgment){
	
	// Wrap the judgment's XML in a paragraph
	// Changed use of E4X to DOMParser/Serializer
	var judgmentXML = document.createDocumentFragment()
	
	// Split the textual representation to get the single judgments
	var judgmentLines = judgment.split("\n");
	
	// Add all of the judgments to the judgment paragraph
	for(var i = 0; i < judgmentLines.length; i++){
		
		// Between two consecutive judgments: add a linebreak
		if(i != 0){
			var brElement = document.createElementNS("http://www.w3.org/1999/xhtml","br");
			judgmentXML.appendChild(brElement);
		}
		
		// Check if the current judgment is a critical one (i.e. if it is marked with the "<crit>"-tags)
		if(Crossbear.startsWith(judgmentLines[i], "<crit>") && Crossbear.endsWith(judgmentLines[i], "</crit>")){
			
			// Add a critical judgment to the judgment paragraph (color:red and weight:bold)
			// TODO: This use of font is horribly deprecated - beautify
			var fontElement = document.createElementNS("http://www.w3.org/1999/xhtml","font");
			fontElement.setAttribute("color","red");
			var bElement = document.createElementNS("http://www.w3.org/1999/xhtml","b");
			var bContent = document.createTextNode(judgmentLines[i].substr(6,judgmentLines[i].length-13));
			bElement.appendChild(bContent);
			fontElement.appendChild(bElement);
			judgmentXML.appendChild(fontElement);
/* kept for comparison
			judgmentXML.appendChild(<html:font color="red" xmlns:html="http://www.w3.org/1999/xhtml" ><html:b>{judgmentLines[i].substr(6,judgmentLines[i].length-13)}</html:b></html:font>); */
			
		} else {
			
			// Add a normal judgment to the judgment paragraph
			var normalContent = document.createTextNode(judgmentLines[i]);
			judgmentXML.appendChild(normalContent);
			//judgmentXML.appendChild(<>{judgmentLines[i]}</>);
			
		}
	}

	// Finally: return the judgment paragraph
	return judgmentXML;
};

/**
 * Initialization function (called once when the dialog is about to display). This function sets all GUI-elements according to the window.arguments[0].inn-parameters and creates a timer that will periodically execute the bringToFrontAndCheckShutdown-function.
 */
function onLoad() {

	// Display the "Trust" & "Don't Trust" buttons or the "Retry" & "Deactivate Protector" buttons depending on whether a timeout occurred or not
	document.getElementById('crossbear-buttonBox').hidden = window.arguments[0].inn.wasTimeout;
	document.getElementById('crossbear-timeoutButtonBox').hidden = !window.arguments[0].inn.wasTimeout;

	// Put the rating in the dialog's "server-reply"-box
	document.getElementById('crossbear-serverReplyRating').value = window.arguments[0].inn.rating;

	// Get the div that is used to display the judgment
	var srd = document.getElementById("crossbear-serverReplyDiv");
	
	// Set the judgment text
	var nodes = {};
	srd.appendChild(convertJudgmentToXML(window.arguments[0].inn.judgment), document, nodes);
	// This is the old method with E4X:
	// srd.appendChild(Crossbear.xmlToDOM(convertJudgmentToXML(window.arguments[0].inn.judgment), document, nodes));
	
	// If the judgment div became too big: Limit its width
	if(srd.offsetWidth>415){
		srd.style.width = "415px";
	} 

	// Color the rating based on whether it is below or above the user's ratingToTrustAutomatically-value
	if (window.arguments[0].inn.rating > window.arguments[0].inn.ratingToTrustAutomatically) {

		// If it's above: color the rating green
		document.getElementById('crossbear-serverReplyRating').style.color = "#22B14C";

	} else {
		// If it's below: color the rating red
		document.getElementById('crossbear-serverReplyRating').style.color = "#FF0000";
	}

	// Resize the window so it is big enough to display its content (especially important on linux-systems)
	window.sizeToContent();

	// Set a Timer to periodically call the bringToFrontAndCheckShutdown-function
	bringToFrontAndCheckShutdownTimer = window.setInterval(function() {
		bringToFrontAndCheckShutdown(window.arguments[0].inn.cbFrontend.cbeventobserver.checkCBServerOnly);
	}, 500);

};



/**
 * In case the server could not be contacted and the user chose to deactivate the Protector, this function will be called
 */
function deactivateProtector() {

	// Call the function that will actually deactivate the Protector
	window.arguments[0].inn.cbFrontend.deactivateProtector(true);
	
	// Accept all pending connections
	window.arguments[0].inn.cbFrontend.cbprotector.acceptAllPendingConnections();

	// Stop the timer that calls the contactCBServer-function ...
	clearInterval(bringToFrontAndCheckShutdownTimer);

	// ... and close the dialog.
	window.close();

}

/**
 * In case the server could not be contacted and the user chose to try to contact the Crossbear server again, this function will be called
 */
function retry() {

	// Contact the Crossbear server again
	window.arguments[0].inn.cbFrontend.cbprotector.requestVerificationFromServer(window.arguments[0].inn.serverCertChain, window.arguments[0].inn.serverCertHash, window.arguments[0].inn.hostIPPort);

	// Stop the timer that calls the contactCBServer-function ...
	clearInterval(bringToFrontAndCheckShutdownTimer);

	// ... and close the dialog.
	window.close();
};

/**
 * This is the function that will add the hostIPPort's "certificate"/"domain"-combination to the local cache.
 * 
 * @param trust "1" if the user want's the certificate to be trusted, else "0"
 * @returns true (So the dialog will close)
 */
function setTrust(trust) {

	// Add a new entry in the CBTrustDecisionCache for the hostIPPort's certificate and domain according to the user's choice of trust and his/hers defaultCacheValidity
	window.arguments[0].inn.cbFrontend.cbprotector.applyNewTrustDecision(window.arguments[0].inn.serverCertHash, window.arguments[0].inn.hostIPPort, trust);

	// Stop the timer that calls the contactCBServer-function ...
	clearInterval(bringToFrontAndCheckShutdownTimer);

	// Return true so the dialog will close
	return true;
};
