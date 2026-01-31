#!/usr/bin/python

import sys, os
import argparse
import subprocess
from enum import IntEnum

class IDABinaryType(IntEnum):
    KERNELCACHE = 0
    KERNEL      = 1
    KEXT_FAT    = 2
    KEXT        = 3
    DYLD        = 4

    def __str__(self):
        if self.value == self.KERNELCACHE:
            return "Apple XNU kernelcache for ARM64e"
        elif self.value in [IDABinaryType.KERNEL, IDABinaryType.KEXT]:
            return "Mach-O"
        elif self.value == IDABinaryType.KEXT_FAT:
            return "Fat Mach-O File, 2"
        elif self.value == IDABinaryType.DYLD:
            return "Apple DYLD cache for arm64e (select module(s))"
        print("WTF")
        sys.exit(0)

class IDARunner(object):
    @staticmethod
    def execute(type: IDABinaryType,  binary: str = None, idbdir: str = None, script: str = None, args: str = None, logfile: str = None, verbose: bool = False):
        command = ["idat", "-A", f"-T{str(type)}"]

        if script and args:
            command.append(f"-S{script} {' '.join(args)}")
        elif script:
            command.append(f"-S{script}")

        if logfile:
            command.append(f"-L{logfile}")

        if idbdir:
            command.append(f"-o{idbdir}")

        command.append(binary)
        if verbose:
            print(command)
        subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

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
