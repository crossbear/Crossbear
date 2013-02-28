"""
The CurServTime message is sent to the client with every hunting
task. The message contains a Timestamp of the current server time and
is used to give the client the ability to send Hunting Task Replies
with a timestamp that is at least roughly equal to the timestamp the
server would have recorded if it had executed the Hunting Task itself
at that time.
"""

from Message import Message
from time    import time

class CurServTime(Message):
    """
    Message to represent the current server time.

    Arguments:
    data -- timestamp (must be 4 byte)
    TODO: why do we need IPv?
    ipv -- IP version (either 4 or 6, integer)

    Extends: Message
    """

    # TODO: why do we need IPv?
    def __init__(self, data, ipv=None):
        """
        Initialiser. Compute the difference between cb server time and local time
        # (in milliseconds) and store it.
        """
        Message.__init__(self, ("CurServTime",), len(data))
        if len(data) != 4:
            raise (ValueError,
                        "Supplied data doesn't have the correct length: " +\
                        str(len(data)))
        self.diff = Message.ba2int(data, "l") - time()
        

    def currentServTime(self):
        """
        Compute an estimate of the current server time. This is the
        local time plus the difference received by the server.
        """
        return long(time() + self.diff)
