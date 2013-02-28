"""
Base for the client side implementations of the Crossbear messaging types.
"""

__author__ = "Vedat Levi Alev"

from struct      import unpack
from struct      import pack



class Message(object):
    """
    Abstract representation of a Crossbear message.

    Arguments:
    length -- number of objects in a message
    """


    # These are the message types. We map each type to a message type
    # number.
    types = {
             # Public IP Notification v4, v6 
             "PipNot" : { 4 : 0, 6 : 1},
             # Public IP Notification request
             "PipReq" : 2,
             # Current server time
             "CurServTime" : 5,
             # hunting task types (by IP version)
             "Sha256Task" : { 4 : 10, 6 : 11},
             # replies for certificates
             "CertRep" : {"New" : 20, "Known" : 21},
             # certificate verification & results
             "CertVer" : {"Req" : 100, "Res": 110}
            }

    # Dictionary that holds minimal length for message types
    minLen = {
                # pipnot -> hmac 32 bytes
               "PipNot" : 32,
               # type, length, task id
               "Sha256Task" : 7
              }



    # TODO: Is there no native method for this?
    # TODO: Rename?
    @staticmethod
    def ba2int(ba, fmt="I"):
        # TODO: I don't understand this comment:
        # XXX does this method really belong here?
        """
        converts a 4 bytes long byte array to the corresponding integer in
        the native endianness.
        """
        fmt = ">" + fmt # network byte order
        return unpack(fmt, str(ba))[0]



    def __init__(self, type, length = 0):
        """
        Constructor for all objects derived from Message.

        Arguments:
        type -- (tuple of Strings)
        """
        self.length = length

        # Check if we are dealing with a known message type.  Directly
        # translates the message type into the assigned message number
        # using the Message.types dictionary.
        try:
            cur = Message.types
            # TODO: what is the variable lvl to mean? Level?
            for lvl in type:
                cur = cur[lvl]
            self.type = cur
        except KeyError:
            # TODO Better log to stderr or OONI?
            print "The message type `%s` is not known to Crossbear." % type
            raise

        # Check if we have IP version information in our message type
        # and set ipLen to the according number of bytes of a IP
        # address. We need this to check if the length of the message
        # is correct.
        if type[-1] == 4:
            self.ipLen = 4
        elif type[-1] == 6:
            self.ipLen = 16
        else:
            # TODO: should we set it to None or to 0?
            self.ipLen = None

        # Check if the message has minimum length (while considering
        # the extra space needed for the IP address).
        try:
            if length < Message.minLen[type] + self.ipLen:
                raise ValueError, ("Raw data is too short: " + str(length))
        except Exception:
            # pass if minimum length or length is not supplied
            # TODO: Interesting - is this also the case in the Java impl?
            pass


    def getBytes(self):
        # Make sure this can only be ever called if overwritten. See
        # http://norvig.com/python-iaq.html for the non-existing
        # "abstract" keyword
        abstract


    # TODO: continue here
    def binary(self):
        """
        Pack the message into a String.

        Returns:
        
        """
        actual = self.getBytes()
        message = pack(">Bh%dc" % len(actual), self.type, self.length + 3, *actual)
        return message
