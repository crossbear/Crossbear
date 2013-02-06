import OpenSSL
from OpenSSL import crypto as ocrypto
import socket




def get_chain(host, port):
    """
    Fetches the chain
    """
    
    # We try TLS first.
    context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # TODO: change to match Java Hunter?
    s.settimeout(10)
    connection = OpenSSL.SSL.Connection(context,s)

    # FIXED: This doesn't work if host is an object of the type IP Adress
    # Convert to string
    connection.connect(("%s" % host,port))

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
        # FIXED: There isn't a method called dump
        cert_list_pem.append(ocrypto.dump_certificate(ocrypto.FILETYPE_PEM, cert))

    return cert_list_pem


