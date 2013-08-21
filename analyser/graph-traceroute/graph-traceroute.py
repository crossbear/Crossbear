#!/usr/bin/python
from database import DB, HuntingTaskResults, TraceElem, Trace
from graphfactory import GraphFactory

db = DB("analyser.config")
gf = GraphFactory()
g = gf.tograph(db.traces(1))
g.draw_to_json("out.json")
