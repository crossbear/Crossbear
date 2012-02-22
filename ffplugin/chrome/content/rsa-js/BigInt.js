// BigInt, a suite of routines for performing multiple-precision arithmetic in
// JavaScript.
//
// Copyright 1998-2005 David Shapiro.
//
// You may use, re-use, abuse,
// copy, and modify this code to your liking, but please keep this header.
// Thanks!
//
// Dave Shapiro
// dave@ohdave.com

// IMPORTANT THING: Be sure to set maxDigits according to your precision
// needs. Use the setMaxDigits() function to do this. See comments below.
//
// Tweaked by Ian Bunning
// Alterations:
// Fix bug in function biFromHex(s) to allow
// parsing of strings of length != 0 (mod 4)

// Changes made by Dave Shapiro as of 12/30/2004:
//
// The BigInt() constructor doesn't take a string anymore. If you want to
// create a BigInt from a string, use biFromDecimal() for base-10
// representations, biFromHex() for base-16 representations, or
// biFromString() for base-2-to-36 representations.
//
// biFromArray() has been removed. Use biCopy() instead, passing a BigInt
// instead of an array.
//
// The BigInt() constructor now only constructs a zeroed-out array.
// Alternatively, if you pass <true>, it won't construct any array. See the
// biCopy() method for an example of this.
//
// Be sure to set maxDigits depending on your precision needs. The default
// zeroed-out array ZERO_ARRAY is constructed inside the setMaxDigits()
// function. So use this function to set the variable. DON'T JUST SET THE
// VALUE. USE THE FUNCTION.
//
// ZERO_ARRAY exists to hopefully speed up construction of BigInts(). By
// precalculating the zero array, we can just use slice(0) to make copies of
// it. Presumably this calls faster native code, as opposed to setting the
// elements one at a time. I have not done any timing tests to verify this
// claim.

// Max number = 10^16 - 2 = 9999999999999998;
//               2^53     = 9007199254740992;

Crossbear.RSA.BigInt = {};

Crossbear.RSA.BigInt.biRadixBase = 2;
Crossbear.RSA.BigInt.biRadixBits = 16;
Crossbear.RSA.BigInt.bitsPerDigit = Crossbear.RSA.BigInt.biRadixBits;
Crossbear.RSA.BigInt.biRadix = 1 << 16; // = 2^16 = 65536
Crossbear.RSA.BigInt.biHalfRadix = Crossbear.RSA.BigInt.biRadix >>> 1;
Crossbear.RSA.BigInt.biRadixSquared = Crossbear.RSA.BigInt.biRadix * Crossbear.RSA.BigInt.biRadix;
Crossbear.RSA.BigInt.maxDigitVal = Crossbear.RSA.BigInt.biRadix - 1;

// maxDigits:
// Change this to accommodate your largest number size. Use setMaxDigits()
// to change it!
//
// In general, if you're working with numbers of size N bits, you'll need 2*N
// bits of storage. Each digit holds 16 bits. So, a 1024-bit key will need
//
// 1024 * 2 / 16 = 128 digits of storage.
//

Crossbear.RSA.BigInt.maxDigits;
Crossbear.RSA.BigInt.ZERO_ARRAY;
Crossbear.RSA.BigInt.bigZero;
Crossbear.RSA.BigInt.bigOne;

Crossbear.RSA.BigInt.BigInt = function (flag)
{
	if (typeof flag == "boolean" && flag == true) {
		this.digits = null;
	}
	else {
		this.digits = Crossbear.RSA.BigInt.ZERO_ARRAY.slice(0);
	}
	this.isNeg = false;
};

Crossbear.RSA.BigInt.setMaxDigits = function (value)
{
	Crossbear.RSA.BigInt.maxDigits = value;
	Crossbear.RSA.BigInt.ZERO_ARRAY = new Array(Crossbear.RSA.BigInt.maxDigits);
	for (var iza = 0; iza < Crossbear.RSA.BigInt.ZERO_ARRAY.length; iza++) Crossbear.RSA.BigInt.ZERO_ARRAY[iza] = 0;
	Crossbear.RSA.BigInt.bigZero = new Crossbear.RSA.BigInt.BigInt();
	Crossbear.RSA.BigInt.bigOne = new Crossbear.RSA.BigInt.BigInt();
	Crossbear.RSA.BigInt.bigOne.digits[0] = 1;
};

Crossbear.RSA.BigInt.setMaxDigits(20);

// The maximum number of digits in base 10 you can convert to an
// integer without JavaScript throwing up on you.
Crossbear.RSA.BigInt.dpl10 = 15;


Crossbear.RSA.BigInt.biCopy = function (bi)
{
	var result = new Crossbear.RSA.BigInt.BigInt(true);
	result.digits = bi.digits.slice(0);
	result.isNeg = bi.isNeg;
	return result;
};

Crossbear.RSA.BigInt.biFromNumber = function (i)
{
	var result = new Crossbear.RSA.BigInt.BigInt();
	result.isNeg = i < 0;
	i = Math.abs(i);
	var j = 0;
	while (i > 0) {
		result.digits[j++] = i & Crossbear.RSA.BigInt.maxDigitVal;
		i >>= Crossbear.RSA.BigInt.biRadixBits;
	}
	return result;
};

Crossbear.RSA.BigInt.reverseStr = function (s)
{
	var result = "";
	for (var i = s.length - 1; i > -1; --i) {
		result += s.charAt(i);
	}
	return result;
};

Crossbear.RSA.BigInt.reverseByteA = function (b){
	var result = [];
	for (var i = b.length-1;i>-1;--i){
		result.push(b[i]);
	}
	return result;
};

Crossbear.RSA.BigInt.hexToChar = new Array('0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                          'a', 'b', 'c', 'd', 'e', 'f');

Crossbear.RSA.BigInt.digitToHex = function (n)
{
	var mask = 0xf;
	var result = "";
	for (var i = 0; i < 4; ++i) {
		result += Crossbear.RSA.BigInt.hexToChar[n & mask];
		n >>>= 4;
	}
	return Crossbear.RSA.BigInt.reverseStr(result);
};

Crossbear.RSA.BigInt.biToHex = function (x)
{
	var result = "";
	for (var i = Crossbear.RSA.BigInt.biHighIndex(x); i > -1; --i) {
		result += Crossbear.RSA.BigInt.digitToHex(x.digits[i]);
	}
	return result;
};

Crossbear.RSA.BigInt.charToHex = function (c)
{
	var ZERO = 48;
	var NINE = ZERO + 9;
	var littleA = 97;
	var littleZ = littleA + 25;
	var bigA = 65;
	var bigZ = 65 + 25;
	var result;

	if (c >= ZERO && c <= NINE) {
		result = c - ZERO;
	} else if (c >= bigA && c <= bigZ) {
		result = 10 + c - bigA;
	} else if (c >= littleA && c <= littleZ) {
		result = 10 + c - littleA;
	} else {
		result = 0;
	}
	return result;
};

Crossbear.RSA.BigInt.hexToDigit = function (s)
{
	var result = 0;
	var sl = Math.min(s.length, 4);
	for (var i = 0; i < sl; ++i) {
		result <<= 4;
		result |= Crossbear.RSA.BigInt.charToHex(s.charCodeAt(i));
	}
	return result;
};

Crossbear.RSA.BigInt.biFromHex = function (s)
{
	var result = new Crossbear.RSA.BigInt.BigInt();
	var sl = s.length;
	for (var i = sl, j = 0; i > 0; i -= 4, ++j) {
		result.digits[j] = Crossbear.RSA.BigInt.hexToDigit(s.substr(Math.max(i - 4, 0), Math.min(i, 4)));
	}
	return result;
};

Crossbear.RSA.BigInt.biFromString = function (s, radix)
{
	var isNeg = s.charAt(0) == '-';
	var istop = isNeg ? 1 : 0;
	var result = new Crossbear.RSA.BigInt.BigInt();
	var place = new Crossbear.RSA.BigInt.BigInt();
	place.digits[0] = 1; // radix^0
	for (var i = s.length - 1; i >= istop; i--) {
		var c = s.charCodeAt(i);
		var digit = Crossbear.RSA.BigInt.charToHex(c);
		var biDigit = Crossbear.RSA.BigInt.biMultiplyDigit(place, digit);
		result = Crossbear.RSA.BigInt.biAdd(result, biDigit);
		place = Crossbear.RSA.BigInt.biMultiplyDigit(place, radix);
	}
	result.isNeg = isNeg;
	return result;
};

Crossbear.RSA.BigInt.biAdd = function (x, y)
{
	var result;

	if (x.isNeg != y.isNeg) {
		y.isNeg = !y.isNeg;
		result = Crossbear.RSA.BigInt.biSubtract(x, y);
		y.isNeg = !y.isNeg;
	}
	else {
		result = new Crossbear.RSA.BigInt.BigInt();
		var c = 0;
		var n;
		for (var i = 0; i < x.digits.length; ++i) {
			n = x.digits[i] + y.digits[i] + c;
			result.digits[i] = n & 0xffff;
			c = Number(n >= Crossbear.RSA.BigInt.biRadix);
		}
		result.isNeg = x.isNeg;
	}
	return result;
};

Crossbear.RSA.BigInt.biSubtract = function (x, y)
{
	var result;
	if (x.isNeg != y.isNeg) {
		y.isNeg = !y.isNeg;
		result = Crossbear.RSA.BigInt.biAdd(x, y);
		y.isNeg = !y.isNeg;
	} else {
		result = new Crossbear.RSA.BigInt.BigInt();
		var n, c;
		c = 0;
		for (var i = 0; i < x.digits.length; ++i) {
			n = x.digits[i] - y.digits[i] + c;
			result.digits[i] = n & 0xffff;
			// Stupid non-conforming modulus operation.
			if (result.digits[i] < 0) result.digits[i] += Crossbear.RSA.BigInt.biRadix;
			c = 0 - Number(n < 0);
		}
		// Fix up the negative sign, if any.
		if (c == -1) {
			c = 0;
			for (var i = 0; i < x.digits.length; ++i) {
				n = 0 - result.digits[i] + c;
				result.digits[i] = n & 0xffff;
				// Stupid non-conforming modulus operation.
				if (result.digits[i] < 0) result.digits[i] += Crossbear.RSA.BigInt.biRadix;
				c = 0 - Number(n < 0);
			}
			// Result is opposite sign of arguments.
			result.isNeg = !x.isNeg;
		} else {
			// Result is same sign.
			result.isNeg = x.isNeg;
		}
	}
	return result;
};

Crossbear.RSA.BigInt.biHighIndex = function (x)
{
	var result = x.digits.length - 1;
	while (result > 0 && x.digits[result] == 0) --result;
	return result;
};

Crossbear.RSA.BigInt.biNumBits = function (x)
{
	var n = Crossbear.RSA.BigInt.biHighIndex(x);
	var d = x.digits[n];
	var m = (n + 1) * Crossbear.RSA.BigInt.bitsPerDigit;
	var result;
	for (result = m; result > m - Crossbear.RSA.BigInt.bitsPerDigit; --result) {
		if ((d & 0x8000) != 0) break;
		d <<= 1;
	}
	return result;
};

Crossbear.RSA.BigInt.biMultiply = function (x, y)
{
	var result = new Crossbear.RSA.BigInt.BigInt();
	var c;
	var n = Crossbear.RSA.BigInt.biHighIndex(x);
	var t = Crossbear.RSA.BigInt.biHighIndex(y);
	var uv, k;

	for (var i = 0; i <= t; ++i) {
		c = 0;
		k = i;
		for (var j = 0; j <= n; ++j, ++k) {
			uv = result.digits[k] + x.digits[j] * y.digits[i] + c;
			result.digits[k] = uv & Crossbear.RSA.BigInt.maxDigitVal;
			c = uv >>> Crossbear.RSA.BigInt.biRadixBits;
		}
		result.digits[i + n + 1] = c;
	}
	// Someone give me a logical xor, please.
	result.isNeg = x.isNeg != y.isNeg;
	return result;
};

Crossbear.RSA.BigInt.biMultiplyDigit = function (x, y)
{
	var n, c, uv;

	result = new Crossbear.RSA.BigInt.BigInt();
	n = Crossbear.RSA.BigInt.biHighIndex(x);
	c = 0;
	for (var j = 0; j <= n; ++j) {
		uv = result.digits[j] + x.digits[j] * y + c;
		result.digits[j] = uv & Crossbear.RSA.BigInt.maxDigitVal;
		c = uv >>> Crossbear.RSA.BigInt.biRadixBits;
	}
	result.digits[1 + n] = c;
	return result;
};

Crossbear.RSA.BigInt.arrayCopy = function (src, srcStart, dest, destStart, n)
{
	var m = Math.min(srcStart + n, src.length);
	for (var i = srcStart, j = destStart; i < m; ++i, ++j) {
		dest[j] = src[i];
	}
};

Crossbear.RSA.BigInt.highBitMasks = new Array(0x0000, 0x8000, 0xC000, 0xE000, 0xF000, 0xF800,
                             0xFC00, 0xFE00, 0xFF00, 0xFF80, 0xFFC0, 0xFFE0,
                             0xFFF0, 0xFFF8, 0xFFFC, 0xFFFE, 0xFFFF);

Crossbear.RSA.BigInt.biShiftLeft = function (x, n)
{
	var digitCount = Math.floor(n / Crossbear.RSA.BigInt.bitsPerDigit);
	var result = new Crossbear.RSA.BigInt.BigInt();
	Crossbear.RSA.BigInt.arrayCopy(x.digits, 0, result.digits, digitCount,
	          result.digits.length - digitCount);
	var bits = n % Crossbear.RSA.BigInt.bitsPerDigit;
	var rightBits = Crossbear.RSA.BigInt.bitsPerDigit - bits;
	for (var i = result.digits.length - 1, i1 = i - 1; i > 0; --i, --i1) {
		result.digits[i] = ((result.digits[i] << bits) & Crossbear.RSA.BigInt.maxDigitVal) |
		                   ((result.digits[i1] & Crossbear.RSA.BigInt.highBitMasks[bits]) >>>
		                    (rightBits));
	}
	result.digits[0] = ((result.digits[i] << bits) & Crossbear.RSA.BigInt.maxDigitVal);
	result.isNeg = x.isNeg;
	return result;
};

Crossbear.RSA.BigInt.lowBitMasks = new Array(0x0000, 0x0001, 0x0003, 0x0007, 0x000F, 0x001F,
                            0x003F, 0x007F, 0x00FF, 0x01FF, 0x03FF, 0x07FF,
                            0x0FFF, 0x1FFF, 0x3FFF, 0x7FFF, 0xFFFF);

Crossbear.RSA.BigInt.biShiftRight = function (x, n)
{
	var digitCount = Math.floor(n / Crossbear.RSA.BigInt.bitsPerDigit);
	var result = new Crossbear.RSA.BigInt.BigInt();
	Crossbear.RSA.BigInt.arrayCopy(x.digits, digitCount, result.digits, 0,
	          x.digits.length - digitCount);
	var bits = n % Crossbear.RSA.BigInt.bitsPerDigit;
	var leftBits = Crossbear.RSA.BigInt.bitsPerDigit - bits;
	for (var i = 0, i1 = i + 1; i < result.digits.length - 1; ++i, ++i1) {
		result.digits[i] = (result.digits[i] >>> bits) |
		                   ((result.digits[i1] & Crossbear.RSA.BigInt.lowBitMasks[bits]) << leftBits);
	}
	result.digits[result.digits.length - 1] >>>= bits;
	result.isNeg = x.isNeg;
	return result;
};

Crossbear.RSA.BigInt.biMultiplyByRadixPower = function (x, n)
{
	var result = new Crossbear.RSA.BigInt.BigInt();
	Crossbear.RSA.BigInt.arrayCopy(x.digits, 0, result.digits, n, result.digits.length - n);
	return result;
};

Crossbear.RSA.BigInt.biDivideByRadixPower = function (x, n)
{
	var result = new Crossbear.RSA.BigInt.BigInt();
	Crossbear.RSA.BigInt.arrayCopy(x.digits, n, result.digits, 0, result.digits.length - n);
	return result;
};

Crossbear.RSA.BigInt.biModuloByRadixPower = function (x, n)
{
	var result = new Crossbear.RSA.BigInt.BigInt();
	Crossbear.RSA.BigInt.arrayCopy(x.digits, 0, result.digits, 0, n);
	return result;
};

Crossbear.RSA.BigInt.biCompare = function (x, y)
{
	if (x.isNeg != y.isNeg) {
		return 1 - 2 * Number(x.isNeg);
	}
	for (var i = x.digits.length - 1; i >= 0; --i) {
		if (x.digits[i] != y.digits[i]) {
			if (x.isNeg) {
				return 1 - 2 * Number(x.digits[i] > y.digits[i]);
			} else {
				return 1 - 2 * Number(x.digits[i] < y.digits[i]);
			}
		}
	}
	return 0;
};

Crossbear.RSA.BigInt.biDivideModulo = function (x, y)
{
	var nb = Crossbear.RSA.BigInt.biNumBits(x);
	var tb = Crossbear.RSA.BigInt.biNumBits(y);
	var origYIsNeg = y.isNeg;
	var q, r;
	if (nb < tb) {
		// |x| < |y|
		if (x.isNeg) {
			q = Crossbear.RSA.BigInt.biCopy(Crossbear.RSA.BigInt.bigOne);
			q.isNeg = !y.isNeg;
			x.isNeg = false;
			y.isNeg = false;
			r = Crossbear.RSA.BigInt.biSubtract(y, x);
			// Restore signs, 'cause they're references.
			x.isNeg = true;
			y.isNeg = origYIsNeg;
		} else {
			q = new Crossbear.RSA.BigInt.BigInt();
			r = Crossbear.RSA.BigInt.biCopy(x);
		}
		return new Array(q, r);
	}

	q = new Crossbear.RSA.BigInt.BigInt();
	r = x;

	// Normalize Y.
	var t = Math.ceil(tb / Crossbear.RSA.BigInt.bitsPerDigit) - 1;
	var lambda = 0;
	while (y.digits[t] < Crossbear.RSA.BigInt.biHalfRadix) {
		y = Crossbear.RSA.BigInt.biShiftLeft(y, 1);
		++lambda;
		++tb;
		t = Math.ceil(tb / Crossbear.RSA.BigInt.bitsPerDigit) - 1;
	}
	// Shift r over to keep the quotient constant. We'll shift the
	// remainder back at the end.
	r = Crossbear.RSA.BigInt.biShiftLeft(r, lambda);
	nb += lambda; // Update the bit count for x.
	var n = Math.ceil(nb / Crossbear.RSA.BigInt.bitsPerDigit) - 1;

	var b = Crossbear.RSA.BigInt.biMultiplyByRadixPower(y, n - t);
	while (Crossbear.RSA.BigInt.biCompare(r, b) != -1) {
		++q.digits[n - t];
		r = Crossbear.RSA.BigInt.biSubtract(r, b);
	}
	for (var i = n; i > t; --i) {
    var ri = (i >= r.digits.length) ? 0 : r.digits[i];
    var ri1 = (i - 1 >= r.digits.length) ? 0 : r.digits[i - 1];
    var ri2 = (i - 2 >= r.digits.length) ? 0 : r.digits[i - 2];
    var yt = (t >= y.digits.length) ? 0 : y.digits[t];
    var yt1 = (t - 1 >= y.digits.length) ? 0 : y.digits[t - 1];
		if (ri == yt) {
			q.digits[i - t - 1] = Crossbear.RSA.BigInt.maxDigitVal;
		} else {
			q.digits[i - t - 1] = Math.floor((ri * Crossbear.RSA.BigInt.biRadix + ri1) / yt);
		}

		var c1 = q.digits[i - t - 1] * ((yt * Crossbear.RSA.BigInt.biRadix) + yt1);
		var c2 = (ri * Crossbear.RSA.BigInt.biRadixSquared) + ((ri1 * Crossbear.RSA.BigInt.biRadix) + ri2);
		while (c1 > c2) {
			--q.digits[i - t - 1];
			c1 = q.digits[i - t - 1] * ((yt * Crossbear.RSA.BigInt.biRadix) | yt1);
			c2 = (ri * Crossbear.RSA.BigInt.biRadix * Crossbear.RSA.BigInt.biRadix) + ((ri1 * Crossbear.RSA.BigInt.biRadix) + ri2);
		}

		b = Crossbear.RSA.BigInt.biMultiplyByRadixPower(y, i - t - 1);
		r = Crossbear.RSA.BigInt.biSubtract(r, Crossbear.RSA.BigInt.biMultiplyDigit(b, q.digits[i - t - 1]));
		if (r.isNeg) {
			r = Crossbear.RSA.BigInt.biAdd(r, b);
			--q.digits[i - t - 1];
		}
	}
	r = Crossbear.RSA.BigInt.biShiftRight(r, lambda);
	// Fiddle with the signs and stuff to make sure that 0 <= r < y.
	q.isNeg = x.isNeg != origYIsNeg;
	if (x.isNeg) {
		if (origYIsNeg) {
			q = Crossbear.RSA.BigInt.biAdd(q, Crossbear.RSA.BigInt.bigOne);
		} else {
			q = Crossbear.RSA.BigInt.biSubtract(q, Crossbear.RSA.BigInt.bigOne);
		}
		y = Crossbear.RSA.BigInt.biShiftRight(y, lambda);
		r = Crossbear.RSA.BigInt.biSubtract(y, r);
	}
	// Check for the unbelievably stupid degenerate case of r == -0.
	if (r.digits[0] == 0 && Crossbear.RSA.BigInt.biHighIndex(r) == 0) r.isNeg = false;

	return new Array(q, r);
};

Crossbear.RSA.BigInt.biDivide = function (x, y)
{
	return Crossbear.RSA.BigInt.biDivideModulo(x, y)[0];
};
