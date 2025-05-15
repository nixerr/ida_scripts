
import idautils
import idaapi
import idc

import importlib.util
import sys

def parse_script_list(path):
    with open(path, 'r') as fd:
        lines = fd.read().split('\n')

    output = {
        'before' : [],
        'after' : []
    }

    for line in lines:
        if line.startswith('#') or line == '':
            continue
        [s, n, p] = line.split(' ')
        output[s].append((n, p))

    return output

def include(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

def run_stage(stage, storage):
    for entry in storage[stage]:
        (name, scr) = entry
        script = include(name, scr)
        script.run()

def main(file):
    outs = parse_script_list(file)
    run_stage('before', outs)
    idc.auto_wait()
    run_stage('after', outs)
    idc.auto_wait()
    idc.qexit(0)

main(idc.ARGV[1])
