from twisted.internet import reactor, defer
from twisted.internet import ssl
from twisted.internet.protocol import ClientFactory, Protocol
from twisted.internet.ssl import ContextFactory
from OpenSSL.SSL import Context, SSLv23_METHOD, TLSv1_METHOD, VERIFY_PEER, VERIFY_FAIL_IF_NO_PEER_CERT




class CertificateFetcher(object):
    """
    This class is responsible for fetching certificates from
    a given host at a given port.
    """
    
    def __init__(self):
        pass
    
    def fetch(self, host, port):
        """
        fetchs the chain
        """
        deferred = defer.Deferred()
        factory  = CertificateFetcherFactory(deferred)
        contextFactory = CertificateContextFactory(deferred)

        reactor.connectSSL(host, int(port), factory, contextFactory)
        return deferred



class MyProtocol(Protocol):
    def __init__(self):
        pass

    def connectionMade(self):
        print "Yay"


class CertificateFetcherFactory(ClientFactory):
    def __init__(self, deferred):
        self.deferred = deferred

    def buildProtocol(self, addr):
        return MyProtocol()

    def clientConnectionFailed(self, connector, reason):
        self.deferred.errback(Exception("Connection failed."))

    def clientConnectionLost(self, connector, reason):
        if not self.deferred.called:
            self.deferred.errback(Exception("Connection lost."))
        
        
class CertificateContextFactory(ContextFactory):
    """
    Context for certificates
    """
    #TODO: Can we do something better than conning SSL by using a verifier?
    isClient = True
    def __init__(self, deferred):
        self.deferred = deferred
    
    def getContext(self):
        ctx =  Context(SSLv23_METHOD)
        ctx.set_verify(VERIFY_PEER | VERIFY_FAIL_IF_NO_PEER_CERT, self.fetch)
        return ctx
    
    def fetch(self, conn, x509, errno, depth, preverifyOK):
        print "Blaaar"
        self.deferred.callback(x509)
        return True
