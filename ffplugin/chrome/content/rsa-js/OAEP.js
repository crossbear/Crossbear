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
 * OAEP is a secure padding scheme for RSA. It is defined in the "PKCS #1 v2.1: RSA Cryptography Standard"
 * 
 * This implementation of the OAEP padding is the result of reverse engineering the org.bouncycastle.crypto.encodings.OAEPEncoding class and translating it to Javascript.
 * 
 * The sourcecode for bouncycastle can be downloaded at http://www.bouncycastle.org/. The license of bouncycastle can be found at http://www.bouncycastle.org/licence.html
 */

// Declare namespace OAEP
var OAEP = {};

/**
 * Convert an integer into a byte[] of length 4. The byte[] will be in network byte-order (i.e. big-endian byte-order).
 * 
 * @param i The Integer to convert
 * @param sp The byte[] holding the converted integer
 */
OAEP.ItoOSP = function(i, sp) {
	sp[0] = (i >>> 24) & 255;
	sp[1] = (i >>> 16) & 255;
	sp[2] = (i >>> 8) & 255;
	sp[3] = i & 255;
};

/**
 * Mask generator function, as described in PKCS1v2.
 * 
 * @param Z A byte[] containing the seed from which the mask is generated
 * @param zOff Offset inside "Z" to take the seed from
 * @param zLen Number of bytes to take from "Z" for seeding
 * @param length Intended length in octets of the mask
 */
OAEP.maskGeneratorFunction1 = function(Z, zOff, zLen, length) {
	
	var mask = [];
	var hashBuf = [];
	var C = new Array(4);
	var counter = 0;

	do {
		OAEP.ItoOSP(counter, C);

		hashBuf = Crypto.SHA1(Z.slice(zOff, zOff + zLen).concat(C), {
			asBytes : true
		});

		mask = mask.concat(hashBuf);

	} while (++counter < Math.floor(length / hashBuf.length));

	if ((counter * hashBuf.length) < length) {
		OAEP.ItoOSP(counter, C);

		hashBuf = Crypto.SHA1(Z.slice(zOff, zOff + zLen).concat(C), {
			asBytes : true
		});

		mask = mask.concat(hashBuf.slice(0, length - (counter * hashBuf.length)));
	}

	return mask;
};

/**
 * OAEP padding, as described in PKCS1v2.
 * 
 * @param inBytes A byte[] containing the unpadded plaintext
 * @param inOff The Offset inside "inBytes" that will be considered as the starting point of the plaintext
 * @param inLen The number of bytes that will be taken from "inBytes" and that will be padded
 */
OAEP.padBlock = function(inBytes, inOff, inLen) {
	
	/*
	 * OAEP padding is performed on 255 byte blocks that are structured like this:
	 * 
	 * 000000000|SENTINEL|INBYTES
	 */

	//Create the leading 0 bytes
	var block = new Array(255 - 1 - inLen);
	for ( var i = 0; i < block.length; i++) {
		block[i] = 0;
	}

	// Add the sentinel
	block.push(1);

	// Add the plaintext
	block = block.concat(inBytes.slice(inOff, inOff + inLen));

	// Now place the hash of the encoding params (which are "" in this implementation) at position 20
	encParamHash = Crypto.SHA1([], {asBytes : true});
	for ( var i = 20; i < 20 + 20; i++) {
		block[i] = encParamHash[i - 20];
	}

	// Generate a random seed of 20 bytes length
	var prng = Components.classes['@mozilla.org/security/random-generator;1'];
	var seed = prng.getService(Components.interfaces.nsIRandomGenerator).generateRandomBytes(20, (new Date).getUTCMilliseconds());
	
	// Mask the message block.
	var mask = OAEP.maskGeneratorFunction1(seed, 0, seed.length, block.length - 20);
	for ( var i = 20; i != block.length; i++) {
		block[i] ^= mask[i - 20];
	}

	// Place the seed at the beginning of the message
	for ( var i = 0; i < 20; i++) {
		block[i] = seed[i];
	}

	// Mask the seed.
	mask = OAEP.maskGeneratorFunction1(block, 20, block.length - 20, 20);
	for ( var i = 0; i != 20; i++) {
		block[i] ^= mask[i];
	}

	// Return the OAEP-encoded plaintext
	return block;
};
