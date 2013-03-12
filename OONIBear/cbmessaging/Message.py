import abc
from MessageTypes import messageNames

class Message(object):
    __metaclass__ = abc.ABCMeta
    
    def createFromBytes(self, message_type, content):
        # Save data so we can reconstruct the original messages later.
        # TODO: Maybe store the content in byte[] form, whatever we
        # need for the crypto algorithms.
        self.length = len(content)
        self.type = message_type
        self.type_name = messageNames[message_type]
        return
    
    @abc.abstractmethod
    def getBytes(self):
        '''Return the message bytes in string form (i.e. packed)''' 
        return
