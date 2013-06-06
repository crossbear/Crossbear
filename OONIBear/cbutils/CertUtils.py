import OpenSSL
from OpenSSL import crypto as ocrypto
import socket
from pprint import pprint
from Crypto.Hash import MD5,SHA256
import ssl
from  itertools import permutations
from binascii import unhexlify



def compute_chain_hashes(chainp):
    result = []
    for p in permutations(chainp):
        servercert = ssl.PEM_cert_to_DER_cert(p[0])
        
        serverhash = SHA256.new(servercert).hexdigest()
        chainhashes = map(lambda x: MD5.new(x).hexdigest(), p[1:])
        concatenated = ''.join(chainhashes).lower()
        result.append(SHA256.new(unhexlify(serverhash + concatenated)).hexdigest().lower())
    return result 
    
        


def get_chain(host, port):
    """
    Fetches the chain and returns certificates as PEM.
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
        cert_list_pem.append(ocrypto.dump_certificate(ocrypto.FILETYPE_PEM, cert).rstrip())

    return cert_list_pem




if __name__ == "__main__":
    c = get_chain("www.facebook.com", 443)
    pprint(c)
    pprint(compute_chain_hashes(c))
    
