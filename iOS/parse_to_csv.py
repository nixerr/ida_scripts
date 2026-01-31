#!/usr/bin/python

__author__ = 'slashd'

import pprint
import json
import sys

import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--input', dest='input', type=str,
                    help='input file from reconstruct_iokit_classes.py')
parser.add_argument('-o', '--output', dest='out', type=str,
                    help='output csv file')

args = parser.parse_args()

parents = {}

def get_class(line):
    a1 = line.split(':')[0]
    a1 = a1.strip(' ')
    return a1.split(' ')[-1]

def get_parent(line):
    a1 = line.strip('\n')
    a1 = a1.strip(' ')
    return a1.split(' ')[-1]

def create_children_node(node):
    result = []

    if node in parents.keys():
        result.append(node + ',')
        for chld in parents[node]:
            ret = create_children_node(chld)
            for i in ret:
                result.append(node + '.' + i)
    else:
        result.append(node + ',0')

    return result


with open(args.input, 'r') as fdr:
    line = fdr.readline()
    while line:
        node = get_class(line)
        parent = get_parent(line)
        print(node + ' -> ' + parent)

        if parent not in parents.keys():
            parents[parent] = []
        # if parent not in nodes.keys():
        #     nodes[parent] = []

        parents[parent].append(node)
        # nodes[parent].append(node)
        # edges.append([node,parent])

        line = fdr.readline()

pprint.pprint(parents)

# output = {}
# output["name"] = "OSMetaClassBase"
# output["children"] = []
head = "OSObject"
output = create_children_node(head)

# for node in parents[head]:
#     output["children"].append({"name": node})

# head = "OSMetaClassBase"

pprint.pprint(output)
fd = open(args.out, "w")
fd.write('id,value\n')
for i in output:
    fd.write(i + '\n')
fd.close()
sys.exit(0)
