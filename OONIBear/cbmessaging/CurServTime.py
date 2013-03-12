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
        # get four bytes from data and convert them to long. Signed long???
        # Python documentation says that time() returns a float.
        self.diff = (unpack(">l", data[:4])[0]) - time()
        

    def currentServTime(self):
        """
        Compute an estimate of the current server time. This is the
        local time plus the difference received by the server.
        """
        return long(time() + self.diff)

    def getBytes(self):
        # Note: This uses the current client time.
        return pack(">l", time())
