from httplib import HTTPSConnection
from X509toPubKey import extractPubKey
from Crypto.Hash import SHA256  
import ssl

class SingleTrustHTTPS(HTTPSConnection):
    """
    This implements the client side of an https connection where the
    client only trusts a single (given) certificate.

    Arguments:
    cert -- certificate to trust explicitly
    *args -- arguments to HTTPSConnection(*args) -- see there
    """
    def __init__(self, cert, *args):
        try:
            # read the certificate
            c   = open(cert, "r").read()
            # extract the publickey information
            pki = extractPubKey(c)
            # store its SHA256 hash
            self.pHash = SHA256.new(pki).digest()
        except:
            raise IOError, ("Can't open certificate: %s" % cert)
        
        HTTPSConnection.__init__(self, *args)
    

    def connect(self):
        """
        Connect to the HTTPs server.
        """
        HTTPSConnection.connect(self)
        # get the server certificate
        derc  = self.sock.getpeercert(True)
        # the following conversion is a bit backwards
        # but seems to do the trick
        pemc  = ssl.DER_cert_to_PEM_cert(derc)
        # extract the public key info
        spki  = extractPubKey(pemc)
        # compute the sha256 hash
        sHash = SHA256.new(spki).digest()

        # compare the certificates
        if self.pHash != sHash:
            raise ValueError, "Certificate of the server could not be validated!"
        

