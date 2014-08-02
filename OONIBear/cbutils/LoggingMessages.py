
# TODO: Log traceroute?    
class HTSuccessMsg:
    def __init__(self, htid, host, hostip, serverhashes, cert):
        self.htid = htid
        self.host = host
        self.hostip = hostip
        self.serverhashes = " ".join(serverhashes)
        self.cert = cert

    def __str__(self):
        return "HuntingTaskSuccess | %d | %s | %s | %s | %s" % (self.htid, self.host, self.hostip, self.serverhashes, self.cert)



class VerifySuccessMsg:
    def __init(self, host, hostip, rating, judgementstring):
        self.host = host
        self.hostip = hostip
        self.rating = rating
        self.judgementstring = judgementstring
        

    def __str__(self):
        return "VerifyTaskSuccess | %s | %s | %s | %s" % (self.host, self.hostip, self.rating, self.judgementstring)


class HTFailMsg:
    def __init__(self, htid, host, hostip, msg):
        self.message = msg
        self.htid = htid
        self.host = host
        self.hostip = hostip

    def __str__(self):
        return "HuntingTaskFailure | %d | %s | %s | %s" % (self.htid, self.host, self.hostip, self.message)

class VerifyFailureMsg:
    def __init__(self, host, hostip, msg):
        self.message = msg
        self.host = host
        self.hostip = hostip

    def __str__(self):
        return "VerifyFailure | %s | %s | %s" % (self.host, self.hostip, self.message)

        
