#!/usr/bin/python

from ida_runner import IDABinaryType, IDARunner

import os
import time
import argparse
import threading

def arguments():
    parser = argparse.ArgumentParser(
        description = 'Analyzing Kernelcache with plugins'
    )
    parser.add_argument('-k', '--kernelcache', required=True,
        help = 'Path to kernelecache for analyzing')
    parser.add_argument('-o', '--output', default=None,
        help = 'Output directory for IDB file')
    parser.add_argument('-l', '--log', default=None,
        help = 'Path to log file')
    parser.add_argument('-r', '--run', default="run.txt",
        help = 'Path to file with plugins')
    parser.add_argument('-d', '--default', default=False, action="store_true", 
        help = 'Set log file and output by default (in kernelcache\'s directory)')
    parser.add_argument('-f', '--follow', default=False, action="store_true", 
        help = 'Print log file in the console')

    return parser.parse_args()

def follow(path, stop_event, poll=0.1):
    # wait for the file to appear
    while not os.path.exists(path):
        if stop_event.is_set():
            return
        time.sleep(0.05)

    with open(path) as f:
        while True:
            line = f.readline()
            if line:
                print(line, end="", flush=True)
            elif stop_event.is_set():
                for rest in f:      # drain final writes
                    print(rest, end="", flush=True)
                break
            else:
                time.sleep(poll)

def main(args):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    kernelcache_dir = os.path.dirname(os.path.abspath(args.kernelcache))

    if args.default:
        args.log = os.path.join(kernelcache_dir, 'output.txt')
        args.output = os.path.join(kernelcache_dir, f'{os.path.basename(args.kernelcache)}.i64')

    stop = None
    if args.follow and args.log:
        stop = threading.Event()
        t = threading.Thread(target=follow, args=(args.log, stop))
        t.start()

    os.environ['IDA_KCACHE_ALL'] = '1'
    os.environ['IDA_KCU_NO_HARVEST'] = '1'

    IDARunner.set_idapro_path("/Applications/IDA Professional 9.5.app/Contents/MacOS")
    IDARunner.execute(
        type    = IDABinaryType.KERNELCACHE,
        binary  = args.kernelcache,
        script  = os.path.join(script_dir, 'analyze.py'),
        logfile = args.log,
        args    = [os.path.join(script_dir, args.run)],
        idbdir  = args.output
    )

    if stop is not None:
        stop.set()
        t.join()

if __name__ == '__main__':
    main(arguments())
