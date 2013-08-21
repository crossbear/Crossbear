import graph

class GraphFactory(object):
    
    def __init__(self, **options):
        self.options = options

    # Return all other sources that have gotten this certificate (CVR or Server)
    def sources_for_certificate(self, cert, certlist, type):
        return filter(lambda x: x.hash == cert.hash and x.type == type, certlist)

    def comes_from_server(self, cert, certlist):
        return self.sources_for_certificate(cert, certlist, "CrossbearServer") == []

    def comes_from_cvr(self, cert, certlist):
        return self.sources_for_certificate(cert, certlist, "CrossbearCVR") == []

    def tograph(self, result):
        g = graph.Graph()
        htrs = result.results()
        for htr in htrs:
            t = htr.trace()
            for te in t.trace_elems():
                for i in te.ips():
                    g.add_node(i)
                    g.add_node_attribute(i, "geo", te.geo(i))
                    g.add_node_attribute(i, "asn", te.asn(i))
            for i in t.trace_elems()[0].ips():
                g.add_node_attribute(i, "start", "true")
                g.add_node_attribute(i, "fromserver", self.comes_from_server(htr.cert(), result.certificates()))
                g.add_node_attribute(i, "fromcvr", self.comes_from_cvr(htr.cert(), result.certificates()))
            for i in t.trace_elems()[-1].ips():
                g.add_node_attribute(i, "end", "true")
            for i in range(1, len(t.trace_elems())):
                lastelements = t.trace_elem(i - 1)
                thiselements = t.trace_elem(i)
                for ip1 in lastelements.ips():
                    for ip2 in thiselements.ips():
                        g.add_edge(ip1, ip2)
        return g
