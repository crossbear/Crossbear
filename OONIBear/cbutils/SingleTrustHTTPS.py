from   httplib import HTTPSConnection
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
        self.cert = cert
        HTTPSConnection.__init__(self, *args)
    

    def connect(self):
        """
        Connect to the HTTPs server.
        """
        HTTPSConnection.connect(self)
        # get server's certificate in DER format
        derc  = self.sock.getpeercert(True)
        # convert trusted certificate to DER
        servd = ssl.PEM_cert_to_DER_cert(open(self.cert, "r").read())


        # TODO: future versions should pin to the public key,
        # not to the entire certificate. Will make it easier
        # to replace/renew the certificate.
        # Ticket is opened and assigned to Ralph.

        # compare the certificates
        if derc != servd:
            raise ValueError, "Certificate of the server could not be validated!"
        

