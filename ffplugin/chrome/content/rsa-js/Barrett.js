// BarrettMu, a class for performing Barrett modular reduction computations in
// JavaScript.
//
// Requires BigInt.js.
//
// Copyright 2004-2005 David Shapiro.
//
// You may use, re-use, abuse, copy, and modify this code to your liking, but
// please keep this header.
//
// Thanks!
// 
// Dave Shapiro
// dave@ohdave.com 

Crossbear.RSA.Barrett = {

	BarrettMu_modulo : function(x) {
		var q1 = Crossbear.RSA.BigInt.biDivideByRadixPower(x, this.k - 1);
		var q2 = Crossbear.RSA.BigInt.biMultiply(q1, this.mu);
		var q3 = Crossbear.RSA.BigInt.biDivideByRadixPower(q2, this.k + 1);
		var r1 = Crossbear.RSA.BigInt.biModuloByRadixPower(x, this.k + 1);
		var r2term = Crossbear.RSA.BigInt.biMultiply(q3, this.modulus);
		var r2 = Crossbear.RSA.BigInt.biModuloByRadixPower(r2term, this.k + 1);
		var r = Crossbear.RSA.BigInt.biSubtract(r1, r2);
		if (r.isNeg) {
			r = Crossbear.RSA.BigInt.biAdd(r, this.bkplus1);
		}
		var rgtem = Crossbear.RSA.BigInt.biCompare(r, this.modulus) >= 0;
		while (rgtem) {
			r = Crossbear.RSA.BigInt.biSubtract(r, this.modulus);
			rgtem = Crossbear.RSA.BigInt.biCompare(r, this.modulus) >= 0;
		}
		return r;
	},

	BarrettMu_multiplyMod : function(x, y) {
		/*
		 * x = this.modulo(x); y = this.modulo(y);
		 */
		var xy = Crossbear.RSA.BigInt.biMultiply(x, y);
		return this.modulo(xy);
	},

	BarrettMu_powMod : function(x, y) {
		var result = new Crossbear.RSA.BigInt.BigInt();
		result.digits[0] = 1;
		var a = x;
		var k = y;
		while (true) {
			if ((k.digits[0] & 1) != 0)
				result = this.multiplyMod(result, a);
			k = Crossbear.RSA.BigInt.biShiftRight(k, 1);
			if (k.digits[0] == 0 && Crossbear.RSA.BigInt.biHighIndex(k) == 0)
				break;
			a = this.multiplyMod(a, a);
		}
		return result;
	},

	BarrettMu : function(m) {
		this.modulus = Crossbear.RSA.BigInt.biCopy(m);
		this.k = Crossbear.RSA.BigInt.biHighIndex(this.modulus) + 1;
		var b2k = new Crossbear.RSA.BigInt.BigInt();
		b2k.digits[2 * this.k] = 1; // b2k = b^(2k)
		this.mu = Crossbear.RSA.BigInt.biDivide(b2k, this.modulus);
		this.bkplus1 = new Crossbear.RSA.BigInt.BigInt();
		this.bkplus1.digits[this.k + 1] = 1; // bkplus1 = b^(k+1)
		this.modulo = Crossbear.RSA.Barrett.BarrettMu_modulo;
		this.multiplyMod = Crossbear.RSA.Barrett.BarrettMu_multiplyMod;
		this.powMod = Crossbear.RSA.Barrett.BarrettMu_powMod;
	}

};