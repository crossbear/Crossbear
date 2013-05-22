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
 * This is a simple dialog that is meant to inform the user about a possible attack against his system
 */ 
  

/**
 * Initialization function (called once when the dialog is about to display)
 */
function onLoad() {

	// Get a reference for the warning text div
	var wtd = document.getElementById("crossbear-warning-text-div");
	
	// Set the crossbear-warning-text according to the threat that the user should be warned about
	var nodes = {};
	wtd.appendChild(Crossbear.xmlToDOM(window.arguments[0].inn.warningXML, document, nodes));

	//Disable the "I understand" button
	document.documentElement.getButton("accept").disabled = true;
	
	// Reactivate it after "window.arguments[0].inn.timeoutSec"-seconds
	window.setTimeout(function() {
		document.documentElement.getButton("accept").disabled = false;
	}, 1000 * window.arguments[0].inn.timeoutSec);
	
	// Resize the window so it is big enough to display its content (especially important on linux-systems)
	window.sizeToContent();
}



/**
 * "I understand" button pressed
 * 
 * @returns true (i.e. the dialoge will be closed)
 */
function ok() {
	//do nothing ;)
	return true;
};
