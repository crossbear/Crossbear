"""
The tracerouting functionality for PyHunter.
"""

import socket

class Tracer(object):

    """
    Tracer class for implementing a traceroute.
    Arguments:
    mHops -- number of hops that should be taken into account before terminating the traceroute (integer)
    sperHop -- number of samples to be taken per hop (i.e. sent with same TTL)
    """

    # TODO: rename these variables in init
    def __init__(self, mHops, sperHop):
        self.mHops   = mHops
        self.sperHop = sperHop


    # TODO: can we replace this with OONI's traceroute or do we insist
    # on having our own for comparability?
    def traceroute(self, dst , dst_port=3880, src_port=3000):
        """
        Carry out a traceroute to a destination.
        Arguments:
        dst -- destination host, an IP address 
        """
        # TODO: document
        recv = socket.getprotobyname('icmp')
        send = socket.getprotobyname('udp')
        # We start at TTL = 1 hop
        ttl    = 1
        hops   = []
        success = False
        for ttl in range(1, self.mHops):
            if success:
                break
            samples = []
            for _ in range(self.sperHop):
                # initialize sockets
                recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, recv)
                send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, send)
                # TODO: document choice of timeoute
                recv_sock.settimeout(1)
                send_sock.settimeout(1)
                # TODO: document
                send_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
                recv_sock.bind(("", src_port))

                # send the ping
                send_sock.sendto("", ("%s" % dst, dst_port))
                curr_addr = None

                # TODO: document
                try:
                    _, curr_addr = recv_sock.recvfrom(512)
                    curr_addr = curr_addr[0]
                
                except socket.error:
                    # no message received
                    pass

                finally:
                    send_sock.close()
                    recv_sock.close()
                
                if curr_addr == dst:
                    success = True
                elif curr_addr is not None:
                    samples.append("%s" % curr_addr)
            # TODO: document
            samples = "|".join(samples)
            hops.append(samples)
        # TODO: document
        return "\n".join(filter(lambda x: x, hops)) + ("%s" % dst)

