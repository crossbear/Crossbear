import OpenSSL
from OpenSSL import crypto as ocrypto
import socket



class CertificateFetcher(object):
    """
    This class is responsible for fetching certificates from
    a given host on a given port.
    """
    
    def __init__(self):
        pass
    
    def fetch(self, host, port):
        """
        Fetches the chain
        """

        # We try TLS first.
        context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # TODO: change to match Java Hunter?
        s.settimeout(10)
        connection = OpenSSL.SSL.Connection(context,s)
        connection.connect((host,port))

        # Put the socket in blocking mode
        # TODO: do we need to do that???
        connection.setblocking(1)

        # TODO: what do we do if the peer does not offer any cert at all?
        cert_list = []
        try:
            connection.do_handshake()
            cert_list = connection.get_peer_cert_chain()
            connection.shutdown()
        except OpenSSL.SSL.WantReadError:
            # OK, let's switch to SSL23
            connection_23.shutdown()
            context_23 = OpenSSL.SSL.Context(OpenSSL.SSL.OpenSSL.SSL.SSLv23_METHOD)
            s_23 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # TODO: change to match Java Hunter?
            s.settimeout(10)
            connection_23 = OpenSSL.SSL.Connection(context_23,s_23)
            connection_23.connect((host,port))
            try:
                connection_23.do_handshake()
                cert_list = connection_23.get_peer_cert_chain()
                connection_23.shutdown()
            except OpenSSL.SSL.WantReadError:
                # OK, give up.
                # TODO: leave with different exit code?
                return False
        
        cert_list_pem = []
        for cert in cert_list:
            cert_list_pem.append(ocrypto.dump(ocrypto.FILETYPE_PEM, cert))

        return cert_list_pem
