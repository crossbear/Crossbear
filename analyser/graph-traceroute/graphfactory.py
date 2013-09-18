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
        if "intersecting" in self.options:
            return self.to_intersecting_graph(result)
        else:
            return self.to_regular_graph(result)

    def intersects_bad_trace(self, htr, badhtrs):
        totest = htr.trace()
        badtraces = [h.trace() for h in badhtrs]
        
        for trace_elem in totest.trace_elems():
            for badtrace in badtraces:
                if trace_elem in badtrace.trace_elems():
                    return True
        return False

    # Draw bad certificates first
    def to_intersecting_graph(self,result):
        # first, collect bad traces.
        g = graph.Graph()
        htrs = result.results()
        badhtrs = []
        todraw = []
        for htr in htrs:
            if not self.comes_from_server(htr.certificate(), result.certificates()):
                badhtrs.append(htr)
        todraw.extend(badhtrs)
        # find all intersecting traces
        for htr in htrs:
            if not htr in badhtrs:
                if self.intersects_bad_trace(htr, badhtrs):
                    todraw.append(htr)
        
        return self.htrs_to_graph(todraw, result.certificates())

        
    def htrs_to_graph(self, htrs, certificates):
        g = graph.Graph()
        for htr in htrs:
            t = htr.trace()
            for te in t.trace_elems():
                for i in te.ips():
                    g.add_node(i)
                    g.set_node_attribute(i, "geo", te.geo(i))
                    g.set_node_attribute(i, "asn", te.asn(i))

            g.set_node_attribute(t.source(), "start", "true")
            g.set_node_attribute(t.source(), "fromserver",self.comes_from_server(
                htr.certificate(), certificates))
            g.set_node_attribute(t.source(), "fromcvr",self.comes_from_cvr(
                htr.certificate(), certificates))
            g.set_node_attribute(t.source(), "certificate", htr.certificate().hash())
            g.set_node_attribute(t.target(), "end", "true")
            
            for i in range(1, len(t.trace_elems())):
                lastelements = t.trace_elem(i - 1)
                thiselements = t.trace_elem(i)
                for ip1 in lastelements.ips():
                    for ip2 in thiselements.ips():
                        g.add_edge(ip1, ip2)
                        g.add_edge_attribute(ip1, ip2, "tracesource", t.source())
        return g
            
                

    def to_regular_graph(self, result):
        return self.htrs_to_graph(result.results(), result.certificates());

