#!/usr/bin/python

import sys, os
import pprint
import shutil
import struct
import sqlite3
import argparse
import subprocess
import multiprocessing
from pathlib import Path
from bindiff import BinDiff
from multiprocessing import Pool
from functools import cmp_to_key
from enum import IntEnum


KDK_PATH = 'D:\\work\\apple\\platform\\kdk'
PLG_PATH = "D:\\work\\apple\\tools\\ida_plugins\\ida_scripts\\diffing\\binexp.py"
workspace_out_path = "D:\\work\\apple\\bindiffing\\workspaces\\"
out_path = "D:\\work\\apple\\bindiffing\\out\\"
tmp_path = "D:\\work\\apple\\bindiffing\\tmp\\"


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
    parser.add_argument('-s', '--skip-betas', action="store_true",
        help = 'Skip analyzing BETA versions')
    parser.add_argument('-g', '--generate-idb', action="store_true",
        help = 'Just generate idb files without diffing')
    parser.add_argument('-t', '--threads', type=int, default=16,
        help = 'Number of parallel IDA Pro instances')
    parser.add_argument('-l', '--list', action="store_true",
        help = 'List all available KDK versions')

    return parser.parse_args()


class IDABinaryType(IntEnum):
    KERNELCACHE = 0
    KERNEL      = 1
    KEXT_FAT    = 2
    KEXT        = 3

    def __str__(self):
        if self.value == self.KERNELCACHE:
            return "Apple XNU kernelcache for ARM64e"
        elif self.value in [IDABinaryType.KERNEL, IDABinaryType.KEXT]:
            return "Mach-O"
        elif self.value == IDABinaryType.KEXT_FAT:
            return "Fat Mach-O File, 2"
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


class KDK():
    def __init__(self, path: Path):
        self.path: Path = path.resolve()
        self.version = self.path.name[4:-4]
        self.is_beta = KDK.version_is_beta(self.version)

    @staticmethod
    def version_is_beta(v):
        return ord(v[-1]) > 0x60

    def driver(self, name):
        return Driver(self, name)

    def kernel(self, name):
        return Kernel(self, name)

    def handle_driver(self, pool, name):
        driver = self.driver(name)
        driver.handle(pool)

    def handle_kernel(self, pool, name):
        kernel = self.kernel(name)
        kernel.handle(pool)


class KDKStorage():
    def __init__(self, path: Path):
        self.storage_path: Path = path.resolve()
        self.versions: list[KDK] = []
        self.hashmap_versions = {}
        self.scan_kdk_directory()

    @staticmethod
    def compare_kdk_version(v1: KDK, v2: KDK):
        return KDKStorage.compare_version(v1.version, v2.version)

    @staticmethod
    def compare_version(v1, v2):
        n1 = v1.split('_')[0].split('.')
        n2 = v2.split('_')[0].split('.')

        for i in range(max(len(n1), len(n2))):
            if i < len(n1) and i < len(n2):
                if n1[i] == n2[i]:
                    continue
                if n1[i] < n2[i]:
                    return -1
                elif n1[i] > n2[i]:
                    return 1
            elif i < len(n1) and i >= len(n2):
                return 1
            elif i >= len(n1) and i < len(n2):
                return -1

        if KDK.version_is_beta(v1) == True and KDK.version_is_beta(v2) == False:
            return -1
        elif KDK.version_is_beta(v1) == False and KDK.version_is_beta(v2) == True:
            return 1

        if v1.split('_')[1] < v2.split('_')[1]:
            return -1
        else:
            return 1


    def scan_kdk_directory(self) -> list:
        for kdk_path in self.storage_path.iterdir():
            if kdk_path.is_dir():
                kdk = KDK(kdk_path)
                self.versions.append(kdk)
                self.hashmap_versions[kdk.version] = kdk

        self.versions = sorted(self.versions, key=cmp_to_key(KDKStorage.compare_kdk_version))

    def get_versions_list(self, skip_betas: bool):
        versions = []
        for kdk in self.versions:
            if kdk.is_beta and skip_betas:
                continue
            versions.append(kdk.version)
        return versions

    def check_existance(self, versions):
        set(versions).issubset(set(self.hashmap_versions.keys()))


class KDKElement:
    def __init__(self, kdk, name, is_kernel):
        self.is_kernel = is_kernel
        self.name      = name
        self.version   = kdk.version
        self.kdk_path  = kdk.path

    def fini_init(self):
        self.save_dir         = os.path.join(out_path, self.version)
        self.binexport        = f"{self.name}_{self.version}.BinExport"
        self.idb              = f"{self.binary}.i64"
        self.output_dir       = os.path.join(out_path, self.version)
        self.output_binexport = os.path.join(self.output_dir, f"{os.path.basename(self.binexport)}")
        self.output_idb       = os.path.join(self.output_dir, f"{os.path.basename(self.binary)}.i64")

    def is_macho_fat(self):
        with open(self.binary, "rb") as fd:
            return struct.unpack("<I", fd.read(4))[0] == 0xbebafeca

    def run_ida_cmd(self):
        IDARunner.execute(
            type    = IDABinaryType.KEXT_FAT if self.is_macho_fat() else IDABinaryType.KEXT,
            binary  = self.binary,
            script  = PLG_PATH,
            args    = [self.binexport]
        )

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


class Driver(KDKElement):
    element_path = os.path.join('System', 'Library', 'Extensions')
    bin_path = os.path.join('Contents', 'MacOS')
    def __init__(self, kdk: KDK, name):
        super().__init__(kdk, name, False)
        self.kdk_driver_dir = os.path.join(self.kdk_path, Driver.element_path, f"{name}.kext")
        self.binary = os.path.join(self.kdk_driver_dir, Driver.bin_path, self.name)
        self.fini_init()


class Kernel(KDKElement):
    element_path = os.path.join('System', 'Library', 'Kernels')
    def __init__(self, kdk: KDK, name):
        super().__init__(kdk, name, True)
        self.binary = os.path.join(self.kdk_path, Kernel.element_path, self.name)
        self.fini_init()


class BinDiffWorkSpace():
    def __init__(self, name):
        self.name = name
        self.path = os.path.join(workspace_out_path, self.name)
        self.existed_diffs = []
        if os.path.exists(self.path) == False:
            os.mkdir(self.path)
        self.init_db()
        self.load()

    def init_db(self):
        self.db_path = os.path.join(self.path, f"{self.name}.BinDiffWorkspace")

        create_table = False
        if os.path.exists(self.db_path) == False:
            create_table = True

        self.con = sqlite3.connect(self.db_path)
        if create_table:
            cur = self.con.cursor()
            cur.execute("CREATE TABLE diffs(matchesDbPath, isfunctiondiff)")
            self.con.commit()

    def load(self):
        for diff in os.scandir(self.path):
            if diff.is_dir():
                [v1, v2] = diff.name.split(' x ')
                self.existed_diffs.append((v1, v2))

    def diff_dir(self, v1, v2):
        return os.path.join(self.path, f"{v1} x {v2}")

    def is_diff_exists(self, v1, v2):
        return (v1, v2) in self.existed_diffs

    def is_binexport_exists(self, v):
        return os.path.exists(os.path.join(out_path, v, f"{self.name}_{v}.BinExport"))

    def add_diff(self, v1, v2):
        if self.is_binexport_exists(v1) == False or self.is_binexport_exists(v2) == False:
            return
        diff_dir = self.diff_dir(v1, v2)
        os.mkdir(diff_dir)
        path_to_v1_binexport = os.path.join(out_path, v1, f"{self.name}_{v1}.BinExport")
        path_to_v2_binexport = os.path.join(out_path, v2, f"{self.name}_{v2}.BinExport")
        final_path_v1 = os.path.join(diff_dir, os.path.basename(path_to_v1_binexport))
        final_path_v2 = os.path.join(diff_dir, os.path.basename(path_to_v2_binexport))
        shutil.copyfile(path_to_v1_binexport, final_path_v1)
        shutil.copyfile(path_to_v2_binexport, final_path_v2)
        result_diff_name = f"{self.name}_{v1}_vs_{self.name}_{v2}.BinDiff"
        diff = BinDiff.from_binexport_files(final_path_v1, final_path_v2, os.path.join(diff_dir,result_diff_name))
        self.add_diff_to_db(f"{v1} x {v2}\\{result_diff_name}")

    def add_diff_to_db(self, p):
        cur = self.con.cursor()
        cur.execute(f"INSERT INTO diffs(matchesDbPath, isfunctiondiff) VALUES('{p}', 0)")
        self.con.commit()

    def sort_db(self):
        cur = self.con.cursor()
        entries = cur.execute("SELECT matchesDbPath FROM diffs").fetchall()
        entries = [x[0] for x in entries]
        entries = sorted(entries, key=cmp_to_key(sort_entries))
        cur.execute("DELETE FROM diffs")
        for entry in entries:
            cur.execute(f"INSERT INTO diffs(matchesDbPath, isfunctiondiff) VALUES('{entry}', 0)")
        self.con.commit()


def generate_binexport(m):
    print(f"[i] Generating binexport for {m.name}_{m.version}")
    m.run_ida_cmd()
    m.create_output_dir()
    m.commit()


def sort_entries(e1, e2):
    return KDKStorage.compare_version(e1.split(' x ')[0], e2.split(' x ')[0])


def main():
    args = arguments()
    storage = KDKStorage(Path(KDK_PATH))

    if args.list == True:
        for kdk in storage.versions:
            msg = f"{kdk.version}"
            if kdk.is_beta:
                msg = f"{msg} (beta)"
            print(msg)
        return

    if args.versions != None:
        if storage.check_existance(args.versions) == False:
            for version in args.versions:
                if version not in storage.hashmap_versions.keys():
                    print(f"[-] Not found version : {version}")
            return
        version_to_compare = sorted(args.versions, key=cmp_to_key(KDKStorage.compare_version))

    if args.all == True:
        version_to_compare = storage.get_versions_list(args.skip_betas)

    pool = Pool(processes=args.threads)
    for version in version_to_compare:
        kdk = storage.hashmap_versions[version]

        for driver_name in args.drivers:
            kdk.handle_driver(pool, driver_name)

        for kernel_name in args.kernels:
            kdk.handle_kernel(pool, kernel_name)

    pool.close()
    pool.join()

    if args.generate_idb == True or len(version_to_compare) == 1:
        return

    version_pairs = []
    for x in range(len(version_to_compare) - 1):
        version_pairs.append((version_to_compare[x], version_to_compare[x+1]))

    for driver_name in args.drivers:
        ws = BinDiffWorkSpace(driver_name)
        for vp in version_pairs:
            (v1, v2) = vp
            if ws.is_diff_exists(v1, v2) == False:
                ws.add_diff(v1, v2)
        ws.sort_db()

    for kernel_name in args.kernels:
        ws = BinDiffWorkSpace(kernel_name)
        for vp in version_pairs:
            (v1, v2) = vp
            if ws.is_diff_exists(v1, v2) == False:
                ws.add_diff(v1, v2)
        ws.sort_db()


if __name__ == '__main__':
    main()
