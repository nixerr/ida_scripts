#/usr/bin/python3

import sys
import os

from functools import cmp_to_key
from pathlib import Path
import argparse
import string

# run the next command to import lldb correctly:
# export PYTHONPATH=`lldb -P`
import lldb
import re

KDK_PATH = "/Users/vsh/Research/platform/kdk"

def arguments():
    parser = argparse.ArgumentParser(
        prog = 'diff',
        description = 'Generate binexport files for specific driver and version'
    )

    parser.add_argument('-k', '--kernel', required="--list" not in sys.argv and "-l" not in sys.argv,
        help = 'Choose kernel')
    parser.add_argument('-l', '--list', action="store_true",
        help = 'List all available KDK versions')
    parser.add_argument('-f', '--find', action="store_true", default=False,
        help = 'Find structures with type')
    parser.add_argument('-v', '--version', required="--list" not in sys.argv and "-l" not in sys.argv,
        help = 'Choose version')
    parser.add_argument('-s', '--struct', required=False,
        help = 'Choose struct name')
    # parser.add_argument('-r', '--recursive', action="store_true", default=False,
    #     help = 'Print subtypes')

    return parser.parse_args(args=None if sys.argv[1:] else ['--help'])


class VT(object):
    Black        = "\033[38;5;0m"
    DarkRed      = "\033[38;5;1m"
    DarkGreen    = "\033[38;5;2m"
    Brown        = "\033[38;5;3m"
    DarkBlue     = "\033[38;5;4m"
    DarkMagenta  = "\033[38;5;5m"
    DarkCyan     = "\033[38;5;6m"
    Grey         = "\033[38;5;7m"

    DarkGrey     = "\033[38;5;8m"
    Red          = "\033[38;5;9m"
    Green        = "\033[38;5;10m"
    Yellow       = "\033[38;5;11m"
    Blue         = "\033[38;5;12m"
    Magenta      = "\033[38;5;13m"
    Cyan         = "\033[38;5;14m"
    White        = "\033[38;5;15m"

    Default      = "\033[39m"

    Bold         = "\033[1m"
    EndBold      = "\033[22m"

    Oblique      = "\033[3m"
    EndOblique   = "\033[23m"

    Underline    = "\033[4m"
    EndUnderline = "\033[24m"

    Reset        = "\033[0m"


class NOVT(object):
    def __getattribute__(self, *args):
        return ""

class IndentScope(object):
    def __init__(self, O):
        self._O = O

    def __enter__(self):
        self._O._indent += '    '

    def __exit__(self, exc_type, exc_value, traceback):
        self._O._indent = self._O._indent[:-4]


def _get_num_formatter(ctx, fmt_hex, fmt_dec):
    """ Returns a number formatter.
    
    params:
        ctx - configuration context
        fmt_hex - hexadecimal format
        fmt_dec - decimal format
    returns:
        number formatter
    """
    O = ctx[0]
    use_hex = ctx[1]
    if use_hex:
        fmt = fmt_hex
    else:
        fmt = fmt_dec
    return lambda n: O.format(fmt, n)


def _get_offset_formatter(ctx, fmt_hex, fmt_dec):
    """ Returns a formatter of struct member offsets and sizes.
    
    params:
        ctx - configuration context
        fmt_hex - hexadecimal format
        fmt_dec - decimal format
    returns:
        offset formatter
    """
    O = ctx[0]
    use_hex = ctx[1]
    if use_hex:
        fmt = fmt_hex
    else:
        fmt = fmt_dec
    return lambda o, s: O.format(fmt, o, s)


_xnu_core_default_formatter = string.Formatter()


def xnu_format(fmt, *args, **kwargs):
    """ Conveniency function to call SBValueFormatter().format """
    return _xnu_core_default_formatter.vformat(fmt, args, kwargs)


def xnu_vformat(fmt, args, kwargs):
    """ Conveniency function to call SBValueFormatter().vformat """
    return _xnu_core_default_formatter.vformat(fmt, args, kwargs)


class CommandOutput(object):
    """
    An output handler for all commands. Use Output.print to direct all output of macro via the handler.
    These arguments are passed after a "--". eg
    (lldb) zprint -- -o /tmp/zprint.out.txt

    Currently this provide capabilities
    -h show help
    -o path/to/filename
       The output of this command execution will be saved to file. Parser information or errors will
       not be sent to file though. eg /tmp/output.txt
    -s filter_string
       the "filter_string" param is parsed to python regex expression and each line of output
       will be printed/saved only if it matches the expression.
       The command header will not be filtered in any case.
    -p <plugin_name>
       Send the output of the command to plugin.
    -v ...
       Up verbosity
    -c <always|never|auto>
       configure color
    """
    def __init__(self, cmd_name, CommandResult=None, fhandle=None):
        """ Create a new instance to handle command output.
        params:
                CommandResult : SBCommandReturnObject result param from lldb's command invocation.
        """
        self.fname=None
        self.fhandle=fhandle
        self.FILTER=False
        self.pluginRequired = False
        self.pluginName = None
        self.cmd_name = cmd_name
        self.resultObj = CommandResult
        self.verbose_level = 0
        self.target_cmd_args = []
        self.target_cmd_options = {}
        self._indent = ''
        self._buffer = ''

        self._header = None
        self._lastHeader = None
        self._line = 0

        self.color = None
        self.isatty = os.isatty(sys.__stdout__.fileno())
        self.VT = VT if self._doColor() else NOVT()

    def _doColor(self):
        if self.color is True:
            return True;
        return self.color is None and self.isatty

    def _needsHeader(self):
        if self._header is None:
            return False
        if self._lastHeader is None:
            return True
        if not self.isatty:
            return False
        return self._line - self._lastHeader > 40

    def indent(self):
        return IndentScope(self)

    def table(self, header, indent = False):
        return HeaderScope(self, header, indent)

    def format(self, s, *args, **kwargs):
        kwargs['VT'] = self.VT
        return xnu_vformat(s, args, kwargs)

    def error(self, s, *args, **kwargs):
        print(self.format("{cmd.cmd_name}: {VT.Red}"+s+"{VT.Default}", cmd=self, *args, **kwargs))

    def write(self, s):
        """ Handler for all commands output. By default just print to stdout """

        o = self.fhandle or self.resultObj

        for l in (self._buffer + s).splitlines(True):
            if l[-1] != '\n':
                self._buffer = l
                return

            if self.FILTER:
                if not self.reg.search(l):
                    continue
                l = self.reg.sub(self.VT.Underline + r"\g<0>" + self.VT.EndUnderline, l);

            if len(l) == 1:
                o.write(l)
                self._line += 1
                continue

            if len(l) > 1 and self._needsHeader():
                for h in self._header.splitlines():
                    o.write(self.format("{}{VT.Bold}{:s}{VT.EndBold}\n", self._indent, h))
                self._lastHeader = self._line

            o.write(self._indent + l)
            self._line += 1

        self._buffer = ''

    def flush(self):
        if self.fhandle != None:
            self.fhandle.flush()

    def __del__(self):
        """ closes any open files. report on any errors """
        if self.fhandle != None and self.fname != None:
            self.fhandle.close()

    def setOptions(self, cmdargs, cmdoptions =''):
        """ parse the arguments passed to the command
            param :
                cmdargs => [] of <str> (typically args.split())
                cmdoptions : str - string of command level options.
                             These should be CAPITAL LETTER options only.
        """
        opts=()
        args = cmdargs
        cmdoptions = cmdoptions.upper()
        try:
            opts,args = getopt.gnu_getopt(args,'hvo:s:p:c:'+ cmdoptions,[])
            self.target_cmd_args = args
        except getopt.GetoptError as err:
            raise ArgumentError(str(err))
        #continue with processing
        for o,a in opts :
            if o == "-h":
                # This is misuse of exception but 'self' has no info on doc string.
                # The caller may handle exception and display appropriate info
                raise ArgumentError("HELP")
            if o == "-o" and len(a) > 0:
                self.fname=os.path.normpath(os.path.expanduser(a.strip()))
                self.fhandle=open(self.fname,"w")
                print("saving results in file ",str(a))
                self.fhandle.write("(lldb)%s %s \n" % (self.cmd_name, " ".join(cmdargs)))
                self.isatty = os.isatty(self.fhandle.fileno())
            elif o == "-s" and len(a) > 0:
                self.reg = re.compile(a.strip(),re.MULTILINE|re.DOTALL)
                self.FILTER=True
                print("showing results for regex:",a.strip())
            elif o == "-p" and len(a) > 0:
                self.pluginRequired = True
                self.pluginName = a.strip()
                #print "passing output to " + a.strip()
            elif o == "-v":
                self.verbose_level += 1
            elif o == "-c":
                if a in ["always", '1']:
                    self.color = True
                elif a in ["never", '0']:
                    self.color = False
                else:
                    self.color = None
                self.VT = VT if self._doColor() else NOVT()
            else:
                o = o.strip()
                self.target_cmd_options[o] = a


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

    def get_kernel(self, version, name):
        if version in self.hashmap_versions.keys():
            return Kernel(self.hashmap_versions[version], name)
        return None


class KDKElement:
    def __init__(self, kdk: KDK, name, is_kernel):
        self.is_kernel = is_kernel
        self.name      = name
        self.version   = kdk.version
        self.kdk_path  = kdk.path


class Driver(KDKElement):
    element_path = os.path.join('System', 'Library', 'Extensions')
    bin_path = os.path.join('Contents', 'MacOS')
    def __init__(self, kdk: KDK, name):
        super().__init__(kdk, name, False)
        self.kdk_driver_dir = os.path.join(self.kdk_path, Driver.element_path, f"{name}.kext")
        self.binary = os.path.join(self.kdk_driver_dir, Driver.bin_path, self.name)


class Kernel(KDKElement):
    element_path = os.path.join('System', 'Library', 'Kernels')
    def __init__(self, kdk: KDK, name):
        super().__init__(kdk, name, True)
        self.binary = os.path.join(self.kdk_path, Kernel.element_path, self.name)


_UnionStructClass = [ lldb.eTypeClassStruct, lldb.eTypeClassClass, lldb.eTypeClassUnion ]

def print_matches(matches, needle_type_name, show_fields=True):
    print(f"Structures containing '{needle_type_name}':\n")
    for kind, name, size, sbtype in sorted(matches, key=lambda x: x[1]):
        print(f"  {kind:<8} {size:#8x}  {name}")

        if show_fields:
            # Print only the fields that match (or wrap) the needle
            for i in range(sbtype.GetNumberOfFields()):
                field = sbtype.GetFieldAtIndex(i)
                ft    = field.GetType().GetCanonicalType()
                base  = ft
                ptr   = False
                while base.IsPointerType() or base.IsReferenceType():
                    base = base.GetPointeeType().GetCanonicalType()
                    ptr  = True
                if base.GetName() == needle_type_name:
                    offset = field.GetOffsetInBytes()
                    print(f"    +{offset:#06x}  {field.GetType().GetName():<40} {field.GetName()}")
        print("")

    print(f"\n{len(matches)} match(es) found")


def print_types(types):
    # for kind, name, size in sorted(types, key=lambda x: x[1]):
    for kind, name, size in types:
        print(f"{kind:<8} {size:#8x}  {name}")

    print(f"\n{len(types)} types found")


class FieldRepresentation:
    def __init__(self):
        pass


class StructureRepresentation:
    def __init__(self):
        pass



class LLDBKernel:
    def __init__(self, kernel, version):
        self.kernel = kernel
        self.version = version
        self._init_debugger()
        self._init_target()

    def _init_debugger(self):
        self.debugger = lldb.SBDebugger.Create()
        self.debugger.SetAsync(False)
        self.debugger.HandleCommand("settings set target.load-script-from-symbol-file false")

    def _init_target(self):
        self.target = self.debugger.CreateTarget(self.kernel)
        if not self.target.IsValid():
            raise RuntimeError("Failed to create target")

    def _showStructPacking(self, ctx, symbol, begin_offset=0, symsize=0, typedef=None, outerSize=0, memberName=None):
        """ Recursively parse the field members of structure.
            
            params :
                ctx - context containing configuration settings and the output formatter (standard.py) symbol (lldb.SBType) reference to symbol in binary
            returns:
                string containing lines of output.
        """

        O = ctx[0]
        format_offset = _get_offset_formatter(ctx, "{:#06x},[{:#6x}]", "{:04d},[{:4d}]")
        format_num = _get_num_formatter(ctx, "{:#04x}", "{:2d}")

        ctype = "unknown type"
        is_union = False
        is_class = False
        union_size = None
        sym_size = symbol.GetByteSize()

        if symbol.GetTypeClass() == lldb.eTypeClassUnion:
            ctype = "union"
            is_union = True
            union_size = sym_size
        if symbol.GetTypeClass() == lldb.eTypeClassStruct:
            ctype = "struct"
        if symbol.GetTypeClass() == lldb.eTypeClassClass:
            ctype = "class"
            is_class = True

        outstr = O._indent
        if not outerSize or outerSize == sym_size:
            outstr += format_offset(begin_offset, sym_size)
        elif outerSize < sym_size: # happens with c++ inheritance
            outstr += format_offset(begin_offset, outerSize)
        else:
            outstr += O.format("{:s}{VT.DarkRed}{{{:s}}}{VT.Default}",
                    format_offset(begin_offset, sym_size),
                    format_num(outerSize - sym_size))

        if typedef:
            outstr += O.format(" {0}", typedef)
        if symbol.IsAnonymousType():
            outstr += O.format(" ({VT.DarkMagenta}anonymous {0}{VT.Default})", ctype)
        else:
            outstr += O.format(" ({VT.DarkMagenta}{0} {1}{VT.Default})", ctype, symbol.GetName())
        if memberName:
            outstr += O.format(" {0} {{", memberName)
        else:
            outstr += ") {"

        print(outstr)

        with O.indent():
            _previous_size = 0
            _packed_bit_offset = 0
            _nfields = symbol.GetNumberOfFields()

            if is_class:
                _next_offset_in_bits = 0
                _nclasses = symbol.GetNumberOfDirectBaseClasses()

                for i in range(_nclasses):
                    member = symbol.GetDirectBaseClassAtIndex(i)
                    if i < _nclasses - 1:
                        m_size_bits = symbol.GetDirectBaseClassAtIndex(i + 1).GetOffsetInBits()
                    elif _nfields:
                        m_size_bits = symbol.GetFieldAtIndex(0).GetOffsetInBits()
                    else:
                        m_size_bits = symbol.GetByteSize() * 8

                    m_offset = member.GetOffsetInBytes() + begin_offset
                    m_type = member.GetType()
                    m_name = member.GetName()
                    m_size = m_size_bits // 8

                    _previous_size = m_size
                    _packed_bit_offset = member.GetOffsetInBits() + m_size_bits

                    self._showStructPacking(ctx, m_type, m_offset, str(m_type), outerSize=m_size, memberName=m_name)

            for i in range(_nfields):
                member = symbol.GetFieldAtIndex(i)
                m_offset = member.GetOffsetInBytes() + begin_offset
                m_offset_bits = member.GetOffsetInBits()

                m_type = member.GetType()
                m_name = member.GetName()
                m_size = m_type.GetByteSize()

                if member.IsBitfield():
                    m_is_bitfield = True
                    m_size_bits = member.GetBitfieldSizeInBits()
                else:
                    m_is_bitfield = False
                    m_size_bits = m_size * 8

                if not is_union and _packed_bit_offset < m_offset_bits:
                    m_previous_offset = begin_offset + (_packed_bit_offset // 8)
                    m_hole_bits = m_offset_bits - _packed_bit_offset
                    if _packed_bit_offset % 8 == 0:
                        print(O.format("{:s}{:s} ({VT.DarkRed}*** padding ***{VT.Default})", O._indent,
                               format_offset(m_previous_offset, (m_hole_bits // 8))))
                    else:
                        print(O.format("{:s}{:s} ({VT.Brown}*** padding : {:s} ***{VT.Default})", O._indent,
                                format_offset(m_previous_offset, _previous_size),
                                format_num(m_hole_bits)))

                _previous_size = m_size
                _packed_bit_offset = m_offset_bits + m_size_bits

                _type_class = m_type.GetTypeClass()
                _canonical_type = m_type.GetCanonicalType()
                _canonical_type_class = m_type.GetCanonicalType().GetTypeClass()

                if _type_class == lldb.eTypeClassTypedef and _canonical_type_class in _UnionStructClass:
                    self._showStructPacking(ctx, _canonical_type, m_offset, str(m_type), outerSize=union_size, memberName=m_name)
                elif _type_class in _UnionStructClass:
                    self._showStructPacking(ctx, m_type, m_offset, outerSize=union_size, memberName=m_name)
                else:
                    outstr = O._indent
                    outstr += format_offset(m_offset, m_size)
                    if is_union and union_size != (m_size_bits // 8):
                        outstr += O.format("{VT.DarkRed}{{{:s}}}{VT.Default}",
                                format_num(union_size - (m_size_bits // 8)))
                    if m_is_bitfield:
                        outstr += O.format(" ({VT.DarkGreen}{:s} : {:s}{VT.Default}) {:s}",
                                m_type.GetName(),
                                format_num(m_size_bits),
                                m_name)
                    else:
                        outstr += O.format(" ({VT.DarkGreen}{:s}{VT.Default}) {:s}",
                                m_type.GetName(), m_name)
                    print(outstr)

            referenceSize = sym_size
            if outerSize:
                referenceSize = min(outerSize, sym_size)

            if not is_union and _packed_bit_offset < referenceSize * 8:
                m_previous_offset = begin_offset + (_packed_bit_offset // 8)
                m_hole_bits = referenceSize * 8 - _packed_bit_offset
                if _packed_bit_offset % 8 == 0:
                    print(O.format("{:s}{:s} ({VT.DarkRed}*** padding ***{VT.Default})", O._indent,
                            format_offset(m_previous_offset, m_hole_bits // 8)))
                else:
                    print(O.format("{:s}{:s} ({VT.Brown}padding : {:s}{VT.Default})\n", O._indent,
                            format_offset(m_previous_offset, _previous_size),
                            format_num(m_hole_bits)))

        print(f"{O._indent}}}")

    def dump_struct_layout(self, ty_name, O):
        type_list = self.target.FindTypes(ty_name)
        if type_list.GetSize() == 0:
            print(f"Type '{ty_name}' not found")
            return

        sym = type_list.GetTypeAtIndex(0)
     
        if sym.GetTypeClass() == lldb.eTypeClassTypedef:
            sym = sym.GetCanonicalType()

        if sym.GetTypeClass() not in _UnionStructClass:
            return O.error("{0} is not a structure/union/class type", ty_name)

        ctx = (O, True)
        self._showStructPacking(ctx, sym, 0)
    
    def list_types(self):
        WANTED = {lldb.eTypeClassStruct, lldb.eTypeClassUnion, lldb.eTypeClassClass, lldb.eTypeClassEnumeration}

        seen = set()
        types = []
        for i in range(self.target.GetNumModules()):
            module = self.target.GetModuleAtIndex(i)
            type_list = module.GetTypes(
                lldb.eTypeClassStruct | lldb.eTypeClassUnion | lldb.eTypeClassClass | lldb.eTypeClassEnumeration
            )
            for j in range(type_list.GetSize()):
                t = type_list.GetTypeAtIndex(j)
                name = t.GetName()
                if not name or name in seen:
                    continue
                seen.add(name)
                tc = t.GetTypeClass()
                kind = {
                    lldb.eTypeClassStruct: "struct",
                    lldb.eTypeClassUnion:  "union",
                    lldb.eTypeClassClass:  "class",
                    lldb.eTypeClassEnumeration : "enum",
                }.get(tc, "?")
                # decl = t.GetDeclaration()
                # fs = decl.GetFileSpec()
                # path = (fs.GetDirectory() or "") + "/" + (fs.GetFilename() or "")
                # types.append((kind, name, t.GetByteSize(), path.lstrip("/")))
                types.append((kind, name, t.GetByteSize()))
        return types

    def find_structs_containing_type(self, needle_type_name, recursive=False):
        COMPOSITE = {lldb.eTypeClassStruct, lldb.eTypeClassUnion, lldb.eTypeClassClass}
        MASK = lldb.eTypeClassStruct | lldb.eTypeClassUnion | lldb.eTypeClassClass

        def canonical_name(t: lldb.SBType) -> str:
            """Strip pointer/ref/typedef layers to get the underlying type name."""
            t = t.GetCanonicalType()
            while t.IsPointerType() or t.IsReferenceType():
                t = t.GetPointeeType().GetCanonicalType()
            return t.GetName() or ""

        def field_matches(field_type: lldb.SBType) -> bool:
            return canonical_name(field_type) == needle_type_name

        def contains_needle(sbtype: lldb.SBType, visited: set) -> bool:
            """
            Check if sbtype has a field whose (dereferenced) type matches needle.
            If recursive=True, also descend into nested composite fields.
            """
            type_name = sbtype.GetName()
            if type_name in visited:
                return False
            visited.add(type_name)

            for i in range(sbtype.GetNumberOfFields()):
                field = sbtype.GetFieldAtIndex(i)
                ft = field.GetType().GetCanonicalType()

                # Direct match (value, pointer, or reference to needle)
                if field_matches(ft):
                    return True

                # Recurse into nested composite types if requested
                if recursive and ft.GetTypeClass() in COMPOSITE:
                    if contains_needle(ft, visited):
                        return True

            return False

        # Collect all composite types from the module
        seen = set()
        matches = []

        for mi in range(self.target.GetNumModules()):
            module = self.target.GetModuleAtIndex(mi)
            type_list = module.GetTypes(MASK)

            for ti in range(type_list.GetSize()):
                t = type_list.GetTypeAtIndex(ti)
                name = t.GetName()
                if not name or name in seen:
                    continue
                seen.add(name)

                if contains_needle(t, set()):
                    kind = {
                        lldb.eTypeClassStruct: "struct",
                        lldb.eTypeClassUnion:  "union",
                        lldb.eTypeClassClass:  "class",
                    }.get(t.GetTypeClass(), "?")
                    matches.append((kind, name, t.GetByteSize(), t))

        return matches


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

    kernel = storage.get_kernel(args.version, args.kernel)
    if kernel == None:
        print(f'[-] Version {args.version} not found!')
        return

    lldb_kernel = LLDBKernel(kernel.binary, args.version)

    if args.struct and args.find:
        matches = lldb_kernel.find_structs_containing_type(args.struct)
        print_matches(matches, args.struct)
    elif args.struct is not None:
        lldb_kernel.dump_struct_layout(args.struct, CommandOutput(''))
        # struct_layout = lldb_kernel.get_struct_layout(args.struct, CommandOutput(''))
        # print_struct(struct_layout)
    else:
        types = lldb_kernel.list_types()
        print_types(types)


if __name__ == '__main__':
    main()
