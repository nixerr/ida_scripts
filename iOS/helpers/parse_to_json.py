#!/usr/bin/python

__author__ = 'slashd'

import pprint
import json
import sys

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
    result = {}
    result["name"] = node

    if node in parents.keys():
        result["children"] = []
        for chld in parents[node]:
            result["children"].append(create_children_node(chld))

    return result


with open('class.def', 'r') as fdr:
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

output = {}
# output["name"] = "OSMetaClassBase"
# output["children"] = []

output = create_children_node("OSMetaClassBase")

# for node in parents[head]:
#     output["children"].append({"name": node})

# head = "OSMetaClassBase"

pprint.pprint(output)
fd = open("iokit.json", "w")
fd.write(json.dumps(output))
fd.close()
sys.exit(0)


for parent_name in parents.keys():
    print("")
    print(parent_name)
    for node in parents[parent_name]:
        if node in parents.keys():
            print("Node " + node + " is parent")
        else:
            print("Node " + node + " is end")

