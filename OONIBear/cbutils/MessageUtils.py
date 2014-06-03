from M2Crypto import X509
from cbmessaging.SignatureMessage import SignatureMessage

def verify(messagelist, servercert):
    messageindex = -1
    for index in range(messagelist.length()):
        message = messagelist.getMessage(index)
        if isinstance(message, SignatureMessage):
            messageindex = index
            break
    if messageindex == -1:
        print "No signature message in message list."
        return 0
    sigmessage = messagelist.getMessage(messageindex)
    messagelist.removeMessage(messageindex)
    toverify = messagelist.getBytes()
    cert = X509.load_cert(servercert)
    pubkey = cert.get_pubkey()
    pubkey.reset_context(md="sha256")
    pubkey.verify_init()
    pubkey.verify_update(toverify)
    return (pubkey.verify_final(sigmessage.signature) == 1)
