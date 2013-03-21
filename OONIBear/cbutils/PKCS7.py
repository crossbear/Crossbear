"""
PKCS7 padding implementation. 

The code is based on code from the following URL, which we gratefully
acknowledge.
http://japrogbits.blogspot.de/2011/02/using-encrypted-data-between-python-and.html

Essentially, it is an implementation of the padding described in
http://tools.ietf.org/html/rfc5652#page-27
"""

# FIXME: I fear we have to reimplement this as we could not clarify
# the license. Thus, we cannot put it under GPL.

import binascii
import StringIO


# TODO: rename to something that makes clear that we only do unpadding
# here
class PKCS7(object):
    """
    PKCS7 padding.

    Arguments:
    k -- input length; as k times octets
    """

    # TODO: do we really need to initialise to k=32? Why?
    def __init__(self, k=32):
        self.k = k


    # TODO: rename to remove_padding()
    def decode(self, text):
        """
        Remove PKCS7 padding from a string.
        
        Arguments:
        text -- input (string)

        Returns:
        String with padding removed.
        """
        length = len(text)
        # Determine the value val = k' that was used for padding. k'
        # depends on the number of octets used in the padding. See RFC
        # 5652 to learn the exact mechanism. Rephrasing from there:
        # "the input shall be padded at the trailing end with k'-(lth
        # mod k') octets *all having value k'-(lth mod k')*, where lth is
        # the length of the input"
        val = int(binascii.hexlify(text[-1]), 16)

        # The value k' must not be larger than our own value k used in
        # the initialisation of this PKCS7Padder instance.
        if val > self.k:
            # FIXME: We should not crash to console here. Detect
            # problem and termine current use of PKCS7
            # gracefully. Suggestion: report to calling function.
            raise ValueError('Input is not padded or padding is corrupt')

        # The value val = k' is used as the value for padding octet,
        # and it appears exactly val = k' times. Thus, we just remove
        # it that often from the input string:
        l = length - val
        return text[:l]
