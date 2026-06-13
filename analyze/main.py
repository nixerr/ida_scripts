#!/usr/bin/python

from ida_runner import IDABinaryType, IDARunner
import os
import argparse

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

    return parser.parse_args()

def main(args):
    IDARunner.set_idapro_path("/Applications/IDAPro_9.3.app/Contents/MacOS")
    IDARunner.execute(
        type    = IDABinaryType.KERNELCACHE,
        binary  = args.kernelcache,
        script  = os.path.abspath('analyze.py'),
        logfile = args.log,
        args    = [os.path.abspath(args.run)],
        idbdir  = args.output
    )

if __name__ == '__main__':
    main(arguments())
