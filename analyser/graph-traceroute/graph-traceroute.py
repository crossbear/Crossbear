#!/usr/bin/python
from database import DB
from graphfactory import GraphFactory
import argparse

parser = argparse.ArgumentParser(description="Graphs crossbear traces.")
parser.add_argument("-i", "--intersecting", action = "store_true")

args = parser.parse_args()
db = DB("analyser.config")
graphoptions = {}
if (args.intersecting):
    graphoptions = {"intersecting": True}
gf = GraphFactory(**graphoptions)
g = gf.tograph(db.traces(1))
g.draw_to_json("out.json")
