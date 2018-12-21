#!/usr/bin/python

__author__ = 'slashd'

import pygraphviz as pgv
from graphviz import Digraph
import pprint
import sys

nodes = {}
edges = []

def get_class(line):
    a1 = line.split(':')[0]
    a1 = a1.strip(' ')
    return a1.split(' ')[-1]

def get_parent(line):
    a1 = line.strip('\n')
    a1 = a1.strip(' ')
    return a1.split(' ')[-1]

with open('class.def', 'r') as fdr:
    line = fdr.readline()
    while line:
        node = get_class(line)
        parent = get_parent(line)
        # print(node + ' -> ' + parent)

        if parent not in nodes.keys():
            nodes[parent] = []

        nodes[parent].append(node)
        edges.append([node,parent])

        line = fdr.readline()

# dot = Digraph('G')
# dot.format = 'svg'
# dot.attr('graph', compound='true', rankdir='LR')
# dot.attr()
# dot.attr('node', shape='box')
# dot.node_attr.update(color='lightblue2', style='filled')
# dot.node('OSMetaClassBase')
# dot.node('OSMetaClass')
# dot.edge('OSMetaClass', 'OSMetaClassBase')
pprint.pprint(nodes)

G = pgv.AGraph(strict='false', overlap='false', splines='true', directed='true', rankdir='LR')
G.node_attr['style'] = 'filled'
G.edge_attr['concentrate']='false'


for parent in nodes.keys():
    # with dot.subgraph(name='cluster_' + parent) as c:
    #     c.attr(fontcolor='white')
        # c.attr('node', shape='box', fillcolor='red:yellow',
        #    style='filled', gradientangle='90')
        # for node in nodes[parent]:
        #     c.node(node)
    for node in nodes[parent]:
        G.add_node(node, label=node)
        G.add_edge(node, parent)

G.add_edge('OSMetaClass', 'OSMetaClassBase')
# for parent in nodes.keys():
#     G.add_subgraph(nodes[parent],name='cluster_' + parent,rank='same')
# for edge in edges:
#     dot.edge(edge[0], edge[1])

G.write("miles.dot")
sys.exit(0)
s = G.string()
with open('VIZJS/template.html', 'r') as fdr:
    with open('VIZJS/index.html', 'w') as fdw:
        line = fdr.readline()
        while line:
            if '__DOT_STRING__' in line:
                line = line.replace('__DOT_STRING__', s)
            fdw.write(line)
            line = fdr.readline()

# G.draw("miles.png",prog='circo')
# G.draw('simple.png', prog="circo")
# dot.view()

