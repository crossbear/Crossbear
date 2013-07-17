#!/usr/bin/python

import pygraphviz as pgv
from pprint import pprint
import cStringIO

class Graph(object):
    
    def __init__(self):
        self.v = {}
        self.e = []
        self.node_attributes = {}
        self.edge_attributes = {}

    def add_node(self, nodename):
        if nodename in self.v:
            pass
        else:
            self.v[nodename] = 1;

    def add_edge(self, nodea, nodeb):
        if not (nodea in self.v and nodeb in self.v):
            raise "Nodes %s or %s not present in node set." % (nodea, nodeb)
        else:
            self.e.append((nodea,nodeb))

    def add_node_attribute(self,nodename, key, value):
        if nodename in self.node_attributes:
            self.node_attributes[nodename][key] = value;
        else:
            self.node_attributes[nodename] = {key: value}
            
    def add_edge_attribute(self,nodea,nodeb, key, value):
        """Edge is passed as a tuple of nodes"""
        edge = (nodea,nodeb)
        if edge in self.edge_attributes:
            self.edge_attributes[edge][key] = value;
        else:
            self.edge_attributes[edge] = {key: value}

    def get_dotgraph(self, dot_attributes = {}):
        g = pgv.AGraph(**dot_attributes)
        for i in self.v:
            if i in self.node_attributes:
                g.add_node(i, **self.node_attributes[i])
            else:
                g.add_node(i)
        for (nodea, nodeb) in self.e:
            if (nodea, nodeb) in self.edge_attributes:
                g.add_edge(nodea, nodeb, **self.edge_attributes[(nodea, nodeb)])
            else:
                g.add_edge(nodea, nodeb)
        return g

    def write_to_file(self, filename, dot_attributes = {}):
        g = self.get_dotgraph(dot_attributes)
        g.layout()
        g.draw(filename)

    def get_dot(self, dot_attributes = {}):
        g = self.get_dotgraph(dot_attributes)
        return g.string()
    
    def get_output_string(self, format, dot_attributes = {}):
        g = self.get_dotgraph(dot_attributes)
        g.layout()
        strfile = cStringIO.StringIO()
        g.draw(strfile, format)
        ret = strfile.getvalue()
        strfile.close()
        return ret
        

if __name__ == "__main__":
    g = Graph()
    g.add_node("Test")
    g.add_node("Test2")
    g.add_edge("Test", "Test2")
    g.add_node_attribute("Test", "color", "#ff0000")
    print g.get_output_string("svg")
