import networkx as nx
import pygraphviz as pgv

Gtmp = pgv.AGraph('callgraph.dot')

trans = dict()
for i in Gtmp.nodes():
    trans[i.name] =  i.attr['label']

G = nx.Graph(Gtmp)
btn = nx.betweenness_centrality(G)

for k in sorted(btn, key=btn.get):
    print trans[k] + " " + str(btn[k])


