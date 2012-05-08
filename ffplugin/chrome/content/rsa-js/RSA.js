// RSA, a suite of routines for performing RSA public-key computations in
// JavaScript.
//
// Requires BigInt.js and Barrett.js.
//
// Copyright 1998-2005 David Shapiro.
//
// You may use, re-use, abuse, copy, and modify this code to your liking, but
// please keep this header.
//
// Thanks!
// 
// Dave Shapiro
// dave@ohdave.com 

Crossbear.RSA = {
		RSAKeyPair : function (encryptionExponent, decryptionExponent, modulus)
{
	this.e = Crossbear.RSA.BigInt.biFromHex(encryptionExponent);
	this.d = Crossbear.RSA.BigInt.biFromHex(decryptionExponent);
	this.m = Crossbear.RSA.BigInt.biFromHex(modulus);
	// We can do two bytes per digit, so
	// chunkSize = 2 * (number of digits in modulus - 1).
	// Since biHighIndex returns the high index, not the number of digits, 1 has
	// already been subtracted.
	this.chunkSize = 2 * Crossbear.RSA.BigInt.biHighIndex(this.m)+1; //Added "+1" so RSAencrypt works with OAEPEncoding :)
	this.radix = 16;
	this.barrett = new Crossbear.RSA.Barrett.BarrettMu(this.m);
},


//Modified version:
// - renamed
// - read bytes instead of string
// - output byte array
// - reverse input so java server does not have to do it ;)
RSAencrypt : function (key, byteInput)
{

	var a = Crossbear.RSA.BigInt.reverseByteA(byteInput);
	var i = byteInput.length;
	
	while (a.length % key.chunkSize != 0) {
		a[i++] = 0;
	}
	
	var output = [];

	var al = a.length;
	var j, k, block;
	for (i = 0; i < al; i += key.chunkSize) {
		block = new Crossbear.RSA.BigInt.BigInt();
		j = 0;
		for (k = i; k < i + key.chunkSize; ++j) {
			block.digits[j] = a[k++];
			block.digits[j] += a[k++] << 8;
		}
		var crypt = key.barrett.powMod(block, key.e);
		output.push.apply(output, Crypto.util.hexToBytes(Crossbear.RSA.BigInt.biToHex(crypt)));
	}

	return output;
},

decryptedString : function (key, s)
{
	var blocks = s.split(" ");
	var result = "";
	var i, j, block;
	for (i = 0; i < blocks.length; ++i) {
		var bi;
		if (key.radix == 16) {
			bi = Crossbear.RSA.BigInt.biFromHex(blocks[i]);
		}
		else {
			bi = Crossbear.RSA.BigInt.biFromString(blocks[i], key.radix);
		}
		block = key.barrett.powMod(bi, key.d);
		for (j = 0; j <= Crossbear.RSA.BigInt.biHighIndex(block); ++j) {
			result += String.fromCharCode(block.digits[j] & 255,
			                              block.digits[j] >> 8);
		}
	}
	// Remove trailing null, if any.
	if (result.charCodeAt(result.length - 1) == 0) {
		result = result.substring(0, result.length - 1);
	}
	return result;
}

};