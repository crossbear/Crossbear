"""
Extract the public key from an x.509 certificate.
"""

# TODO: give this import a nicer name
import Crypto.Util.asn1 as cua
import re


def extractPubKey(cert,format='DER'):
    """
    Extract the public key from an x.509 certificate.

    Arguments:
    cert -- certificate (String; must be in PEM format)
    format -- format of certificate to be returned
              (either 'DER' or 'PEM', default: 'DER')
    """

    # FIXME: check if we're really dealing with PEM format, or at
    # least add code to fail gracefully

    # Delete the first and laste line
    # TODO: this should be easier to do
    _,_,cert = cert.partition('\n')
    cert,_,_ = cert.partition('\n-')

    # Delete all the whitespace
    cert = re.sub("\s+", '', cert)

    # Decode it from base64 into binary
    certd = cert.decode("base64")

    # DerSequence models a DER SEQUENCE element
    # TODO: give variables better names
    ders = cua.DerSequence()
    # decode to DER SEQUENCE
    ders.decode(certd)
 
    # TODO: What is tbs for? Give better variable name.
    # 0 -> tbscertificate
    # 1 -> signature algorithm
    # 2 -> signature value
    tbscert = ders[0]

    # Decode the certificate DER SEQUENCE
    tbscd = cua.DerSequence()
    tbscd.decode(tbscert)

    # 0 -> version
    # 1 -> serial number
    # 2 -> sig
    # 3 -> issuer
    # 4 -> validity
    # 5 -> subject
    # 6 -> subject's pkey
    # 7,8,9 -> optional data
    # If format is DER, directly return the content of SEQUENCE[6]
    if format=='DER':
        return tbscd[6]
    else:
        # If format is PEM, add PEM delimiters and encode to Base64
        return "-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----" % tbscd[6].encode("base64")
