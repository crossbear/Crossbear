from MessageTypes import messageNames

class Message(object):
    
    # Read data from a byte format. All subclasses should implement
    # this, and also call this implementation
    def createFromBytes(self, message_type, content):
        # Save data so we can reconstruct the original messages later.
        # Plus 3 for header.
        self.length = len(content) + 3
        self.type = message_type
        self.type_name = messageNames[message_type]
        return
    
    # Takes the place of the default constructor, since we need a
    # default constructor without arguments in MessageList. All
    # subclasses should implement this and also call this
    # implementation.
    def createFromValues(self, message_type, length):
        self.length = length + 3
        self.type = message_type
        self.type_name = messageNames[message_type]
        return
    
    # For signature purposes, every message class should implement
    # this. However, since we currently only sign three message types,
    # making this an abstract method would be overkill. We just raise
    # an exception here.
    def getBytes(self):
        '''Return the message bytes in string form (i.e. packed)'''
        raise NotImplementedError("getBytes not implemented for class %s", type(self))
        return

    def getType(self):
        return self.type
