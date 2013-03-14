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
from struct import unpack, pack

class CurServTime(Message):
    def createFromBytes(self, msgtype, data):
        """
        Initialiser. Compute the difference between cb server time and local time
        # (in milliseconds) and store it.
        """
        Message.createFromBytes(self, msgtype, data)
        if len(data) != 4:
            raise (ValueError,
                        "Supplied data doesn't have the correct length: " +\
                        str(len(data)))
        # get four bytes from data and convert them to long. Why is this a signed long?
        # Python documentation says that time() returns a float.
        (self.servertime,) = unpack(">l", data[:4])
        self.diff = self.servertime - time()
        

    def currentServTime(self):
        """
        Compute an estimate of the current server time. This is the
        local time plus the difference received by the server.
        """
        return long(time() + self.diff)

    def getBytes(self):
        return pack(">l", self.servertime)
