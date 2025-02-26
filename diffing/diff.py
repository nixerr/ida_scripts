#!/usr/bin/python

import sys, os
import pprint
import argparse
import subprocess
import multiprocessing


kdk_path = 'D:\\work\\apple\\platform\\kdk'
ext_path = os.path.join('System', 'Library', 'Extensions')
krn_path = os.path.join('System', 'Library', 'Kernels')
bin_path = os.path.join('Contents', 'MacOS')
plg_path = "D:\\work\\apple\\tools\\ida_plugins\\ida_scripts\\diffing\\binexp.py"
out_path = "D:\\work\\apple\\bindiffing\\out\\"
ida_cmd  = ["idat64", "-A", "-T\"Mach-O\""]


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
    parser.add_argument('-l', '--list', action="store_true",
        help = 'List all available KDK versions')

    args = parser.parse_args()

    return args


def generate_binexport(target, binexport, move_to):
    cur_ida_cmd = list(ida_cmd)
    cur_ida_cmd.extend(["-S{} {}".format(plg_path, binexport)])
    cur_ida_cmd.extend([target])
    # print(cur_ida_cmd)
    subprocess.run(cur_ida_cmd)
    if os.path.exists(move_to) == False:
        os.mkdir(move_to)
    try:
        os.rename(binexport, os.path.join(move_to, binexport))
    except:
        pass

    try:
        os.rename(target + '.i64', os.path.join(move_to, os.path.basename(target) + '.i64'))
    except:
        pass


def handle_driver(version, driver):
    kdk_version_dir = os.path.join(kdk_path, 'KDK_' + version + '.kdk')
    kdk_driver_dir = os.path.join(
        kdk_version_dir,
        ext_path,
        driver + '.kext')
    if os.path.exists(kdk_driver_dir) == False:
        print(f"[-] Not found driver : {kdk_driver_dir}")
        return

    bin_driver_file = os.path.join(
        kdk_driver_dir,
        bin_path,
        driver
    )

    if os.path.exists(bin_driver_file) == False:
        print(f"[-] Not found driver binary : {bin_driver_file}")
        return

    binexport_name = driver + '_' + version + '.binexport'
    move_to = os.path.join(out_path, version)
    multiprocessing.Process(target=generate_binexport, args=(bin_driver_file, binexport_name, move_to,)).start()


def handle_kernel(version, kernel):
    kdk_version_dir = os.path.join(kdk_path, 'KDK_' + version + '.kdk')
    kdk_kernel_file = os.path.join(
        kdk_version_dir,
        krn_path,
        kernel
    )

    if os.path.exists(kdk_kernel_file) == False:
        printf("f[-] Not found kernel : {kdk_kernel_file}")
        return

    binexport_name = kernel + '_' + version + '.binexport'
    move_to = os.path.join(out_path, version)
    multiprocessing.Process(target=generate_binexport, args=(kdk_kernel_file, binexport_name, move_to,)).start()


def scan_kdk_directory() -> list:
    versions = []
    for kdk in os.scandir(kdk_path):
        if kdk.is_dir():
            version = kdk.name[4:-4]
            versions.append(version)

    return versions


def main():
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

    for version in versions:
        kdk_version_dir = os.path.join(kdk_path, 'KDK_' + version + '.kdk')
        if os.path.exists(kdk_version_dir) == False:
            print(f"[-] Not found version : {kdk_version_dir}")
            continue

        for driver in args.drivers:
            handle_driver(version, driver)

        for kernel in args.kernels:
            handle_kernel(version, kernel)


if __name__ == '__main__':
    main()
