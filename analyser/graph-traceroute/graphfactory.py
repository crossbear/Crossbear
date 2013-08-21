from database import Trace,TraceElem, HuntingTaskResults
import graph

class GraphFactory(object):
    
    def __init__(self, **options):
        self.options = options

    def tograph(self, result):
        g = graph.Graph()
        # TODO: Make relation between Trace, TraceElement and IPs more clear.
        # TODO: List if hunter certificate matches a Server certificate, or a CVR.
        for t in result.traces():
            for te in t.trace_elems():
                for i in te.ips():
                    g.add_node(i)
                    g.add_node_attribute(i, "geo", te.geo(i))
                    g.add_node_attribute(i, "asn", te.asn(i))
            for i in t.trace_elems()[0].ips():
                g.add_node_attribute(i, "start", "true")
            for i in t.trace_elems()[-1].ips():
                g.add_node_attribute(i, "end", "true")
            for i in range(1, len(t.trace_elems())):
                lastelements = t.trace_elem(i - 1)
                thiselements = t.trace_elem(i)
                for ip1 in lastelements.ips():
                    for ip2 in thiselements.ips():
                        g.add_edge(ip1, ip2)
        return g


if __name__ == '__main__':
    t = Trace("server", "12345")
    t.add_trace_elem(TraceElem(["1.1.1.1"],{"1.1.1.1": "3"}, {"1.1.1.1": "Munich"}))
    t.add_trace_elem(TraceElem(["1.1.1.2"],{"1.1.1.2": "3"}, {"1.1.1.2": "Cologne"}))
    t.add_trace_elem(TraceElem(["1.1.2.1", "1.1.2.2"], {"1.1.2.1": "4", "1.1.2.2": "4"}, {"1.1.2.1": "Berlin", "1.1.2.2": "Frankfurt"}))
    t.add_trace_elem(TraceElem(["1.1.3.1"], {"1.1.3.1": "5"}, {"1.1.3.1": "Viechtach"}))

    r = HuntingTaskResults([t])

    gf = GraphFactory()
    g = gf.tograph(r)
    g.draw_to_json()
