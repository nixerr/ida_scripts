#!/usr/bin/python

import sys, os
import pprint
import argparse
import subprocess
import multiprocessing
from multiprocessing import Pool


kdk_path = 'D:\\work\\apple\\platform\\kdk'
ext_path = os.path.join('System', 'Library', 'Extensions')
krn_path = os.path.join('System', 'Library', 'Kernels')
bin_path = os.path.join('Contents', 'MacOS')
plg_path = "D:\\work\\apple\\tools\\ida_plugins\\ida_scripts\\diffing\\binexp.py"
out_path = "D:\\work\\apple\\bindiffing\\out\\"
tmp_path = "D:\\work\\apple\\bindiffing\\tmp\\"
ida_cmd  = ["idat64", "-A", "-T\"Mach-O\""]
pool = None


class KDK:
    def __init__(self, is_kernel, version, name):
        self.is_kernel = is_kernel
        self.name      = name
        self.version   = version
        self.kdk_path  = os.path.join(kdk_path, f"KDK_{version}.kdk")

    def fini_init(self):
        self.save_dir         = os.path.join(out_path, self.version)
        self.binexport        = f"{self.name}_{self.version}.binexport"
        self.idb              = f"{self.binary}.i64"
        self.output_dir       = os.path.join(out_path, self.version)
        self.output_binexport = os.path.join(self.output_dir, f"{os.path.basename(self.binexport)}")
        self.output_idb       = os.path.join(self.output_dir, f"{os.path.basename(self.binary)}.i64")

    def prepare_ida_cmd(self):
        self.ida_cmd = list(ida_cmd)
        self.ida_cmd.extend([f"-S{plg_path} \"{self.binexport}\""])
        self.ida_cmd.extend([self.binary])

    def run_ida_cmd(self):
        self.prepare_ida_cmd()
        subprocess.run(self.ida_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def commit(self):
        os.rename(self.idb, self.output_idb)
        os.rename(self.binexport, self.output_binexport)

    def handle(self, pool):
        self.cleanup()
        if self.need_to_generate_idb() and self.need_to_generate_binexport():
            pool.apply_async(generate_binexport, args=(self,))
        else:
            print(f"[!] Exists({os.path.basename(self.output_idb)}) is {self.need_to_generate_idb() == False}")
            print(f"[!] Exists({os.path.basename(self.output_binexport)}) is {self.need_to_generate_binexport() == False}")

    def cleanup(self):
        if os.path.exists(self.idb):
            os.remove(self.idb)

    def need_to_generate_idb(self):
        return os.path.exists(self.output_idb) == False

    def need_to_generate_binexport(self):
        return os.path.exists(self.output_binexport) == False

    def create_output_dir(self):
        if os.path.exists(self.output_dir) == False:
            os.mkdir(self.output_dir)


class Driver(KDK):
    def __init__(self, version, name):
        super().__init__(False, version, name)
        self.kdk_driver_dir = os.path.join(self.kdk_path, ext_path, f"{name}.kext")
        self.binary = os.path.join(self.kdk_driver_dir, bin_path, self.name)
        self.fini_init()


class Kernel(KDK):
    def __init__(self, version, name):
        super().__init__(True, version, name)
        self.binary = os.path.join(self.kdk_path, krn_path, self.name)
        self.fini_init()


def arguments():
    parser = argparse.ArgumentParser(
        prog = 'diff',
        description = 'Generate binexport files for specific driver and version'
    )

    parser.add_argument('-d', '--drivers', nargs='+', default=[],
        help = 'choose which drivers will be used to generate binexport files')
    parser.add_argument('-k', '--kernels', nargs='+', default=[],
        help = 'Choose which kernels will be used to generate binexport files')
    parser.add_argument('-v', '--versions', nargs='+',
        help = 'Choose which versions will be used to generate binexport files')
    parser.add_argument('-o', '--output',
        help = 'Output directory for binexport files')
    parser.add_argument('-a', '--all', action="store_true",
        help = 'Generate binexports for all available versions')
    parser.add_argument('-t', '--threads', type=int, default=16,
        help = 'Number of parallel IDA Pro instances')
    parser.add_argument('-l', '--list', action="store_true",
        help = 'List all available KDK versions')

    args = parser.parse_args()

    return args


def generate_binexport(m):
    print(f"[i] Generating binexport for {m.name}_{m.version}")
    m.run_ida_cmd()
    m.create_output_dir()
    m.commit()


def handle_driver(version, driver):
    driver = Driver(version, driver)
    driver.handle(pool)


def handle_kernel(version, kernel):
    kernel = Kernel(version, kernel)
    kernel.handle(pool)


def scan_kdk_directory() -> list:
    versions = []
    for kdk in os.scandir(kdk_path):
        if kdk.is_dir():
            version = kdk.name[4:-4]
            versions.append(version)

    return versions


def main():
    global pool
    args = arguments()
    versions = scan_kdk_directory()

    if args.list == True:
        versions = scan_kdk_directory()
        for version in versions:
            print(version)
        return

    if args.versions != None:
        versions = args.versions

    if args.all == True:
        versions = scan_kdk_directory()

    pool = Pool(processes=args.threads)
    for version in versions:
        kdk_version_dir = os.path.join(kdk_path, f"KDK_{version}.kdk")
        if os.path.exists(kdk_version_dir) == False:
            print(f"[-] Not found version : {kdk_version_dir}")
            continue

        for driver in args.drivers:
            handle_driver(version, driver)

        for kernel in args.kernels:
            handle_kernel(version, kernel)

    pool.close()
    pool.join()

if __name__ == '__main__':
    main()
