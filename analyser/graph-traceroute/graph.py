#!/usr/bin/python

from pprint import pprint
import pygraphviz as pgv
import networkx as nx
from networkx.readwrite import json_graph
import json
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
            self.v[nodename] = 1

    def add_edge(self, nodea, nodeb):
        if not (nodea in self.v and nodeb in self.v):
            raise "Nodes %s or %s not present in node set." % (nodea, nodeb)
        elif (nodea, nodeb) in self.e:
            pass
        else:
            self.e.append((nodea,nodeb))

    def set_node_attribute(self,nodename, key, value):
        if nodename in self.node_attributes:
            self.node_attributes[nodename][key] = value;
        else:
            self.node_attributes[nodename] = {key: value}

    def add_edge_attribute(self, nodea, nodeb, key, value):
        val = self.get_edge_attribute(nodea, nodeb, key)
        if val != None:
            val.append(value)
            self.set_edge_attribute(nodea, nodeb, key, val)
        else:
            self.set_edge_attribute(nodea, nodeb, key, [value])
            
    def set_edge_attribute(self,nodea,nodeb, key, value):
        """Edge is passed as a tuple of nodes"""
        edge = (nodea,nodeb)
        if edge in self.edge_attributes:
            self.edge_attributes[edge][key] = value;
        else:
            self.edge_attributes[edge] = {key: value}

    def get_edge_attribute(self, nodea, nodeb, key):
        edge = (nodea, nodeb)
        if edge in self.edge_attributes:
            if key in self.edge_attributes[edge]:
                return self.edge_attributes[edge][key];
        return None

    def get_node_attributes(self, nodename, key):
        if nodename in self.node_attributes:
            if key in self.node_attributes[nodename]:
                return self.node_attributes[nodename][key]
        return None

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
    
    def get_dot_output_string(self, format, dot_attributes = {}):
        g = self.get_dotgraph(dot_attributes)
        g.layout()
        strfile = cStringIO.StringIO()
        g.draw(strfile, format)
        ret = strfile.getvalue()
        strfile.close()
        return ret

    def get_networkx(self):
        g = nx.DiGraph()
        for i in self.v.keys():
            g.add_node(i, **self.node_attributes[i])
        for i in self.e:
            (edgea, edgeb) = i
            g.add_edge(edgea, edgeb, **self.edge_attributes[i])
        return g

    def draw_to_json(self, filename):
        g = self.get_networkx()
        d = json_graph.node_link_data(g)
        json.dump(d, open(filename, 'w'))
        

if __name__ == "__main__":
    g = Graph()
    g.add_node("Test")
    g.add_node("Test2")
    g.add_edge("Test", "Test2")
    g.add_node_attribute("Test", "color", "#ff0000")
    g.append_edge_attribute("Test", "Test2", "testattr", 1)
    g.append_edge_attribute("Test", "Test2", "testattr", 2)
    g.draw_to_json("test.json")
