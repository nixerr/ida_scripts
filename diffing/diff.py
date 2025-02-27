#!/usr/bin/python

import sys, os
import pprint
import shutil
import sqlite3
import argparse
import subprocess
import multiprocessing
from bindiff import BinDiff
from multiprocessing import Pool
from functools import cmp_to_key


kdk_path = 'D:\\work\\apple\\platform\\kdk'
ext_path = os.path.join('System', 'Library', 'Extensions')
krn_path = os.path.join('System', 'Library', 'Kernels')
bin_path = os.path.join('Contents', 'MacOS')
plg_path = "D:\\work\\apple\\tools\\ida_plugins\\ida_scripts\\diffing\\binexp.py"
workspace_out_path = "D:\\work\\apple\\bindiffing\\workspaces\\"
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
        self.binexport        = f"{self.name}_{self.version}.BinExport"
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
        # return os.path.exists(self.diff_dir(v1, v2)) == True
        return (v1, v2) in self.existed_diffs

    def add_diff(self, v1, v2):
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


def compare_version(v1, v2):
    if v1.split('_')[1] < v2.split('_')[1]:
        return -1
    else:
        return 1


def sort_entries(e1, e2):
    if e1.split(' x ')[0].split('_')[1] < e2.split(' x ')[0].split('_')[1]:
        return -1
    else:
        return 1


def version_is_beta(v):
    return ord(v[-1]) > 0x60


def scan_kdk_directory(skip_betas) -> list:
    versions = []
    for kdk in os.scandir(kdk_path):
        if kdk.is_dir():
            version = kdk.name[4:-4]
            if skip_betas == True and version_is_beta(version):
                continue
            versions.append(version)

    versions = sorted(versions, key=cmp_to_key(compare_version))
    return versions


def main():
    global pool
    args = arguments()

    if args.list == True:
        versions = scan_kdk_directory(args.skip_betas)
        for version in versions:
            msg = f"{version}"
            if version_is_beta(version):
                msg = f"{version} (beta)"
            print(msg)
        return

    if args.versions != None:
        versions = sorted(args.versions, key=cmp_to_key(compare_version))

    if args.all == True:
        versions = scan_kdk_directory(args.skip_betas)

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

    if args.generate_idb == True or len(versions) == 1:
        return

    version_pairs = []
    for x in range(len(versions) - 1):
        version_pairs.append((versions[x], versions[x+1]))

    for driver in args.drivers:
        ws = BinDiffWorkSpace(driver)
        for vp in version_pairs:
            (v1, v2) = vp
            if ws.is_diff_exists(v1, v2) == False:
                ws.add_diff(v1, v2)
        ws.sort_db()

    for kernel in args.kernels:
        ws = BinDiffWorkSpace(kernel)
        for vp in version_pairs:
            (v1, v2) = vp
            if ws.is_diff_exists(v1, v2) == False:
                ws.add_diff(v1, v2)
        ws.sort_db()

if __name__ == '__main__':
    main()
