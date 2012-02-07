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
 * This is a simple dialog that is meant to inform the user about a possible attack against his system
 */ 


/**
 * Initialization function (called once when the dialog is about to display)
 */
function onLoad() {

	// Set the warning-text according to the threat that the user should be warned about
	var wtd = document.getElementById("warning-text-div");
	wtd.innerHTML ="<p xmlns=\"http://www.mozilla.org/keymaster/gatekeeper/there.is.only.xul\" width=\"350px\" style=\"color:#FFFFFF; word-wrap: break-word;\">"+window.arguments[0].inn.threat+"</p>";

	//Disable the "I understand" button
	document.documentElement.getButton("accept").disabled = true;
	
	// Reactivate it after "window.arguments[0].inn.timeoutSec"-seconds
	window.setTimeout(function() {
		document.documentElement.getButton("accept").disabled = false;
	}, 1000 * window.arguments[0].inn.timeoutSec);
}



/**
 * "I understand" button pressed
 * 
 * @returns true (i.e. the dialoge will be closed)
 */
function ok() {
	//do nothing ;)
	return true;
}