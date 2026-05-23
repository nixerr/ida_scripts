from ida_idp import ida_segment, ida_ua
import ida_typeinf
import ida_hexrays
import ida_funcs
import idautils
import idc
import ida_nalt
import os
import ida_bytes
from idaemu import *
from dataclasses import dataclass, field


revealed_vtables = []

def atk(addr):
    return hex(addr)

class EmulationWrong(Exception):
    def __inti__(self, static, dynamic):
        self.dynamic = dynamic
        self.static = static
        super().__init__(f"Dynamic != Static ({dynamic} / {static})")

class OSMetaClassConstructorCall:
    def __init__(self, osmetaclass, name, parent, size):
        self.osmetaclass = osmetaclass
        self.name        = name
        self.parent      = parent
        self.size        = size
        self.metaclass_vtable = None
        self.vtable      = None

    def get_name(self):
        return self.name

    def __repr__(self):
        return f'OSMetaClass::OSMetaClass({hex(self.osmetaclass)}, "{self.get_name()}", {hex(self.parent)}, {hex(self.size)}, {hex(self.metaclass_vtable)})'

    @staticmethod
    def parse_string(s):
        global revealed_vtables
        open_bracket = s.find('(')
        close_bracket = s.find(')')
        args = s[open_bracket+1:close_bracket].split(', ')
        m = OSMetaClassConstructorCall(int(args[0], 16), args[1].rsplit('"')[1], int(args[2], 16), int(args[3], 16))
        m.metaclass_vtable = int(args[4], 16)
        revealed_vtables.append(m.metaclass_vtable)
        return m


class myEmu_stage_init(Emu):
    OSMETACLASS_CONSTRUCTOR_ADDR = idc.get_name_ea_simple('__ZN11OSMetaClassC2EPKcPKS_j')
    def __init__(self, start_ea, stack=0xf000100, ssize=3):
        super(myEmu_stage_init, self).__init__(stack, ssize)
        self.start = start_ea
        self.end = idc.get_func_attr(start_ea, FUNCATTR_END) - 4
        self.hooks = []
        self.calls = {}
        self.found_OSMetaClass_calls = 0
        self.static_calls_of_osmetaclass = 0
        self.dynamic_calls_of_osmetaclass = 0
        self.scan_func(self.start, self.end, True)

    def _hook_mem_invalid(self, uc, access, address, size, value, user_data):
        addr = self._alignAddr(address)
        uc.mem_map(addr, PAGE_ALIGN)
        data = self._getOriginData(addr, PAGE_ALIGN)
        uc.mem_write(addr, data)
        return True

    def get_op_regnum(self, addr):
        insn = ida_ua.insn_t()
        ida_ua.decode_insn(insn, addr)
        return insn.ops[0].reg - 0x81

    def op_regnum_to_unicorn(self, regnum):
        match regnum:
            case 0: return UC_ARM64_REG_X0
            case 1: return UC_ARM64_REG_X1
            case 2: return UC_ARM64_REG_X2
            case 3: return UC_ARM64_REG_X3
            case 4: return UC_ARM64_REG_X4
            case 5: return UC_ARM64_REG_X5
            case 6: return UC_ARM64_REG_X6
            case 7: return UC_ARM64_REG_X7
            case 8: return UC_ARM64_REG_X8
            case 9: return UC_ARM64_REG_X9
            case 10: return UC_ARM64_REG_X10
            case 11: return UC_ARM64_REG_X11
            case 12: return UC_ARM64_REG_X12
            case 13: return UC_ARM64_REG_X13
            case 14: return UC_ARM64_REG_X14
            case 15: return UC_ARM64_REG_X15
            case 16: return UC_ARM64_REG_X16
            case 17: return UC_ARM64_REG_X17
            case 18: return UC_ARM64_REG_X18
            case 19: return UC_ARM64_REG_X19
            case 20: return UC_ARM64_REG_X20
            case 21: return UC_ARM64_REG_X21
            case 22: return UC_ARM64_REG_X22
            case 23: return UC_ARM64_REG_X23
            case 24: return UC_ARM64_REG_X24
            case 25: return UC_ARM64_REG_X25
            case 26: return UC_ARM64_REG_X26
            case 27: return UC_ARM64_REG_X27
            case 28: return UC_ARM64_REG_X28
            case 29: return UC_ARM64_REG_X29

    def _hook_mem_access(self, uc, access, address, size, value, user_data):
        global revealed_vtables
        if access == UC_MEM_WRITE and atk(address) in self.calls.keys():

            # Get a register through idapython
            PC = uc.reg_read(UC_ARM64_REG_PC)
            Op0 = self.get_op_regnum(PC)

            # Get a register from first operand
            reg = self.op_regnum_to_unicorn(Op0)

            # Read metaclass_vtable from that register
            metaclass_vtable = uc.reg_read(reg)

            self.calls[atk(address)].metaclass_vtable = metaclass_vtable
            revealed_vtables.append(metaclass_vtable)
            self.dynamic_calls_of_osmetaclass += 1

        elif access == UC_MEM_WRITE and self.traceOption & TRACE_DATA_WRITE:
            self._addTrace("### Memory WRITE at 0x%x, data size = %u, data value = 0x%x" \
                           % (address, size, value))
        elif access == UC_MEM_READ and self.traceOption & TRACE_DATA_READ:
            self._addTrace("### Memory READ at 0x%x, data size = %u" \
                           % (address, size))

    def get_BL_addr(self, addr):
        insn = ida_ua.insn_t()
        ida_ua.decode_insn(insn, addr)
        return insn.ops[0].addr

    def is_BL_insn(self, addr):
        return ida_ua.print_insn_mnem(addr) == 'BL'

    def is_call_osmetaclass_contructor(self, addr):
        if self.is_BL_insn(addr):
            if myEmu_stage_init.OSMETACLASS_CONSTRUCTOR_ADDR == self.get_BL_addr(addr):
                return True
        return False

    def is_success(self):
        return self.static_calls_of_osmetaclass == self.dynamic_calls_of_osmetaclass

    def info(self):
        print(f"        Func -> {hex(self.start)}")
        print(f"        Found calls osmetaclass by emulate -> {self.dynamic_calls_of_osmetaclass}")
        if self.dynamic_calls_of_osmetaclass != self.static_calls_of_osmetaclass:
            print(f"        Found calls osmetaclass by static -> {self.static_calls_of_osmetaclass} !")
        else:
            print(f"        Found calls osmetaclass by static -> {self.static_calls_of_osmetaclass}")

    def my_stub(self, uc, out, args):
        return 0x0

    def hook_OSMetaClass_contructor(self, uc, out, args):
        osmetaclass = args[0]
        name        = args[1]
        parent      = args[2]
        size        = args[3]

        if atk(osmetaclass) in self.calls.keys():
            raise

        name = ida_bytes.get_strlit_contents(name, idc.BADADDR, ida_nalt.STRTYPE_C).decode()
        self.calls[atk(osmetaclass)] = OSMetaClassConstructorCall(osmetaclass, name, parent, size)
        return osmetaclass

    def is_the_same_module(self, address):
        if idc.get_segm_name(self.start) == idc.get_segm_name(address):
            return True
        return False

    def scan_func(self, s, e, r):
        has_osmetaclass_call = False
        c = s
        while c <= e:
            if self.is_BL_insn(c):
                bl_target = self.get_BL_addr(c)
                bl_target_end = idc.get_func_attr(bl_target, FUNCATTR_END) - 4
                if self.is_call_osmetaclass_contructor(c):
                    self.static_calls_of_osmetaclass += 1
                    has_osmetaclass_call = True
                elif r == True:
                    if self.scan_func(bl_target, bl_target_end, False) == False:
                        self.hooks.append(bl_target)
                else:
                    self.hooks.append(bl_target)
            c += 4
        return has_osmetaclass_call

    def emulate(self):
        self._createUc()

        self.alt(myEmu_stage_init.OSMETACLASS_CONSTRUCTOR_ADDR, self.hook_OSMetaClass_contructor, 4, False)
        self.setTrace(TRACE_DATA_WRITE)
        self.setTrace(TRACE_CODE)
        for addr in self.hooks:
            self.alt(addr, self.my_stub, 0, False)

        self._emulate(self.start, self.end, [], 1000000)



def emulate_all_OSMetaClass_constructors():
    # Reconstruct parameters for call's to OSMetaClass::OSMetaClass
    OSMetaClass_calls = []

    for seg_ea in Segments():
        if '__mod_init_func' in idc.get_segm_name(seg_ea):
            seg = ida_segment.getseg(seg_ea)
            name = idc.get_segm_name(seg_ea)
            driver_name = name.split(':')[0]

            start_addr = seg.start_ea
            end_addr = seg.end_ea

            count_init_function = int((end_addr - start_addr) / 8)
            count_osmetaclass_function = 0

            print(f"Driver -> {driver_name}")
            print(f"    __mod_init_func : {hex(start_addr)} - {hex(end_addr)}")
            print(f"    Count Init funcs -> {count_init_function}")

            while start_addr < end_addr:
                function_addr = ida_bytes.get_qword(start_addr)

                if function_addr == 0:
                    break

                emulator = myEmu_stage_init(function_addr)
                emulator.emulate()

                if emulator.is_success() == False:
                    emulator.info()
                    emulator.showTrace()
                    raise EmulationWrong(emulator.dynamic_calls_of_osmetaclass, emulator.static_calls_of_osmetaclass)

                for k in emulator.calls.keys():
                    OSMetaClass_calls.append(emulator.calls[k])

                start_addr += 8

    return OSMetaClass_calls


def get_class(init_calls: list[OSMetaClassConstructorCall], osmetaclass):
    for call in init_calls:
        if call.osmetaclass == osmetaclass:
            return call
    return None


def apply_names(init_calls: list[OSMetaClassConstructorCall]):
    # Rename all gMetaClass pointers and metaclass_vtable pointers
    for call in init_calls:
        class_name = call.get_name()
        if '<' in class_name:
            continue

        class_name_meta = f'__ZN{len(class_name)}{class_name}10gMetaClassE_0'
        metaclass_vtable = f'__ZTVN{len(class_name)}{class_name}9MetaClassE'

        idc.set_name(call.osmetaclass, class_name_meta)
        idc.set_name(call.metaclass_vtable-0x10, metaclass_vtable)


def dump_classes(init_calls: list[OSMetaClassConstructorCall], filename):
    with open(filename, 'w') as fd:
        for call in init_calls:
            class_name = call.get_name()

            if class_name == 'OSMetaClass' or class_name == 'OSObject':
                fd.write(f'class {class_name}\n')
                continue

            class_parent = get_class(init_calls, call.parent)
            class_parent_name = class_parent.get_name()

            fd.write(f'class {class_name}: public {class_parent_name}\n')


known_functions = {
    'OSMetaClass' : {
        0x30 : 'serialize',
        0x68 : 'alloc',
    },
    'OSObject' : {
        0x28 : 'release',
        0x48 : 'refcount',
        0x58 : 'taggedRelease',
        0x70 : 'free',
    },
    'IOUserClient' : {
        0x540 : 'externalMethod',
        0x550 : 'initWithTask',
        0x560 : 'clientClose',
        0x568 : 'clientDied',
        0x578 : 'registerNotificationPort',
        0x590 : 'clientMemoryForType',
        0x5B0 : 'getTargetAndMethodForIndex',
        0x5C8 : 'getTargetAndTrapForIndex',
    },
    'IOUserClient2022' : {
        0x5D0 : 'externalMethod2022',
    },
    'IORegistryEntry' : {
        0xA8 : 'init',
    },
    'IOService' : {
        0x278 : 'systemWillShutdown',
        0x2A8 : 'probe',
        0x2B0 : 'start',
        0x2B8 : 'stop',
        0x2F0 : 'terminate',
        0x460 : 'newUserClient',
        0x468 : 'newUserClient',
        0x4D8 : 'setPowerState',
    },
    'IOMemoryMap' : {
        0x78 : 'getVirtualAddress',
        0x88 : 'getLength',
    },
    'IOMemoryDescriptor' : {
        0xD8 : 'prepare',
        0xE0 : 'complete',
        0xE8 : 'map',
        0x100 : 'makeMapping',
    },
}


known_vtables = []
recheck_calls = []


def is_FFFC_call(addr):
    if ida_ua.print_insn_mnem(addr) == 'ADRL':
        if ida_ua.print_insn_mnem(addr-4) == 'BTI':
            if ida_ua.print_insn_mnem(addr+8) == 'RET':
                return True
    return False


def find_vtables_via_FFFC(init_calls):
    global revealed_vtables
    for call in init_calls:
        revealed_vtables.append(call.metaclass_vtable - 0x10)

    for call in init_calls:
        for xref in idautils.XrefsTo(call.osmetaclass):
            if is_FFFC_call(xref.frm):
                for func_xref in idautils.XrefsTo(xref.frm-4):
                    if is_const(func_xref.frm):
                        vtable = func_xref.frm - 0x48
                        call.vtable = vtable
                        revealed_vtables.append(vtable)


class Hierarchy:
    def __init__(self, init_calls) -> None:
        self.max_depth = 0
        self.hierarchy = {}
        self.init_calls = init_calls
        for call in init_calls:
            self.hierarchy[call.get_name()] = self._convert(call)

        self._finalize()

    def _convert(self, call):
        global revealed_vtables
        vtable = call.vtable
        if vtable is not None:
            vtable = Vtable(self, call.get_name(), vtable)
            revealed_vtables.append(vtable)

        depth = None
        parent = get_class(self.init_calls, call.parent)
        if parent is not None:
            parent = parent.get_name()
        else:
            depth = 0
        return {
            'parent' : parent,
            'vtable' : vtable,
            'size'   : call.size,
            'depth'  : depth,
            'call'   : call,
        }

    def _find_ancestors(self, class_name):
        ancestors = []
        for h in self.hierarchy.keys():
            if self.get_parent(h) == class_name:
                ancestors.append(h)
        return ancestors

    def _find_siblings(self, class_name):
        parent = self.hierarchy[class_name]['parent']
        if parent is None:
            return []

        siblings = []
        for h in self.hierarchy.keys():
            if h == class_name:
                continue
            if self.get_parent(h) == parent:
                siblings.append(h)

        return siblings
    
    def _finalize(self):
        for h in self.hierarchy.keys():
            self.hierarchy[h]['ancestors'] = self._find_ancestors(h)
            self.hierarchy[h]['siblings'] = self._find_siblings(h)
        self._calc_depth()

    def _calc_depth(self):
        seen_unknown = True
        while seen_unknown:
            seen_unknown = False
            for h in self.hierarchy.keys():
                if self.hierarchy[h]['depth'] is None:
                    parent = self.hierarchy[h]['parent']
                    if self.hierarchy[parent]['depth'] is None:
                        seen_unknown = True
                        continue

                    self.hierarchy[h]['depth'] = self.hierarchy[parent]['depth'] + 1
                    if self.max_depth < self.hierarchy[h]['depth']:
                        self.max_depth = self.hierarchy[h]['depth']
                
    def get_siblings(self, class_name):
        return self.hierarchy[class_name]['siblings']

    def get_parent(self, class_name):
        return self.hierarchy[class_name]['parent']

    def get_ancestors(self, class_name):
        return self.hierarchy[class_name]['ancestors']

    def get_size(self, class_name):
        return self.hierarchy[class_name]['size']

    def get_depth(self, class_name):
        return self.hierarchy[class_name]['depth']

    def vtable(self, class_name):
        return self.hierarchy[class_name]['vtable']

    def get_first_non_empty_ancesotr(self, class_name):
        for ancestor in self.all_ancestors((class_name)):
            if self.vtable(ancestor) is not None:
                return ancestor

    def inheritance_list(self, class_name):
        l = [class_name]
        p = self.get_parent(class_name)
        while p is not None:
            l.append(p)
            p = self.get_parent(p)
        return l

    def all_ancestors(self, class_name):
        ancestors = []
        ancestors.extend(self.get_ancestors(class_name))
        for ancestor in self.get_ancestors(class_name):
            ancestors.extend(self.all_ancestors(ancestor))
        return ancestors

    def all_ancestors_with_vtable(self, class_name):
        ancestors = self.all_ancestors(class_name)
        for ancestor in ancestors:
            if self.vtable(ancestor) is None:
                return False
        return True

    def count_all_childs(self, class_name):
        count = len(self.get_ancestors(class_name))
        for child in self.get_ancestors(class_name):
            count += self.count_all_childs(child)
        return count

    def all_classes_without_vtable(self):
        r = []
        for cl in self.hierarchy.keys():
            if self.vtable(cl) is None:
                r.append(cl)
        return r

    def rename_functions(self):
        renames = {}
        for i in range(self.max_depth+1):
            renames[i] = []

        for cl in self.hierarchy.keys():
            if self.vtable(cl) is not None:
                renames[self.get_depth(cl)].append(cl)

        for i in range(self.max_depth+1):
            for cl in renames[i]:
                self.vtable(cl).rename_functions()

    def apply_names(self):
        for cl in self.hierarchy.keys():
            if self.vtable(cl) is not None:
                self.vtable(cl).apply_name()

    def update_vtables(self):
        for class_name in self.hierarchy.keys():
            if self.vtable(class_name) is not None:
                self.vtable(class_name).update_vtable_struct()

    def get_class_declaration(self, class_name):
        s = None
        start = 0
        end = self.get_size(class_name)

        if class_name in ['OSObject', 'OSMetaClass']:
            s =  f'struct __cppobj {class_name} {chr(0x7b)}\n'

            s += f'    {self.vtable(class_name).sanitize_name_struct_vtable()} *__vftable;\n'
            start = 8
        else:
            parent = self.get_parent(class_name)
            s = f'struct __cppobj {NameSanitizer.sanitize_name(class_name)} : {NameSanitizer.sanitize_name(parent)} {chr(0x7b)}\n'
            start = self.get_size(self.get_parent(class_name))

        while start < end:
            s += f'    uint64_t field_{start:x};\n'
            start += 8

        s += '};\n'
        return s

    def create_structures(self):
        structures = {}
        for i in range(self.max_depth+1):
            structures[i] = []

        for cl in self.hierarchy.keys():
            structures[self.get_depth(cl)].append(cl)

        for i in range(self.max_depth+1):
            for class_name in structures[i]:
                tid = idc.get_struc_id(NameSanitizer.sanitize_name(class_name))
                if tid == idc.BADADDR:
                    create_struct(self.get_class_declaration(class_name))
                elif idc.get_struc_size(tid) == 0:
                    # ida_struct.del_struc(get_struc(tid))
                    create_struct(self.get_class_declaration(class_name))



def create_struct(decl: str):
    """
    Parse a C++ struct declaration into the IDB type system.
    Supports __cppobj, inheritance, and nested types.
    """
    til = ida_typeinf.get_idati()
    result = ida_typeinf.parse_decls(
        til,
        decl,
        None,           # printer callback (None = silent)
        ida_typeinf.PT_TYP | ida_typeinf.PT_REPLACE
    )
    if result != 0:
        print(f"[!] parse_decls returned {result} error(s)")
        print(decl)

def is_bit_set(v, b):
    return (v >> b) & 1 == 1

def is_code(addr):
    return '__text' in idc.get_segm_name(addr)

def is_const(addr):
    return '__const' in idc.get_segm_name(addr)

def is_mapped(addr):
    return idc.get_segm_name(addr) != ''

renamed = []

class VtableFunction:
    def __init__(self, vtable, address, offset) -> None:
        self.address = address
        self.paccode = VtableFunction.get_pac(self.address)
        self.function_address = VtableFunction.funcaddr(self.address)
        self.offset = offset
        self.original_name = idc.get_name(self.function_address)
        self.name = None
        self.vtable = vtable

    def all_xrefs_from_const(self) -> bool:
        xrefs = self.xrefs()
        for xref in xrefs:
            if is_const(xref.frm) is not True:
                return False
        return True

    def all_paccodes_are_same(self) -> bool:
        if self.all_xrefs_from_const():
            xrefs = self.xrefs()
            for xref in xrefs:
                if VtableFunction.get_pac(xref.frm) != self.paccode:
                    return False
            return True
        return False

    def xrefs(self):
        return list(idautils.XrefsTo(self.function_address))

    def find_method_name(self, hierarchy):
        l = hierarchy.inheritance_list(self.vtable.name)
        for c in l:
            if c in known_functions.keys():
                if self.offset in known_functions[c]:
                    return known_functions[c][self.offset]

        if self.offset in [0, 8]:
            return 'destructor'

        return 'method'

    def function_name(self):
        if self.name is not None:
            return self.name

        type_name = self.vtable.sanitize_name()

        method = self.find_method_name(self.vtable.hierarchy)
        self.name = f'{type_name}__{method}_0x{self.offset:X}_0x{self.paccode:X}'
        return self.name

    def rename_function(self):
        global renamed
        if self.function_address not in renamed:
            idc.set_name(self.function_address, self.function_name())
            # self.propagate_type()
            renamed.append(self.function_address)
        else:
            self.name = idc.get_name(self.function_address)

    def propagate_type(self):
        first_arg_type = f'{self.vtable.sanitize_name()} *'
        ida_hexrays.init_hexrays_plugin()
        ida_hexrays.decompile(ida_funcs.get_func(self.function_address))
        idc.auto_wait()
        proto = idc.get_type(self.function_address)
        if proto is not None and '()' not in proto and ',' in proto:
            new_proto = proto[0:proto.find('(')+1] + first_arg_type + proto[proto.find(',')]
            idc.SetType(self.function_address, new_proto)

    def __repr__(self) -> str:
        return f'{self.name} : 0x{self.offset:04x} : 0x{self.paccode:04x} : {len(self.xrefs())}'

    @staticmethod
    def is_pac(v):
        return is_bit_set(v, 63)

    @staticmethod
    def get_pac(address):
        return (ida_bytes.get_original_qword(address) >> 32) & 0xFFFF

    @staticmethod
    def funcaddr(address):
        return ida_bytes.get_qword(address)

    @staticmethod
    def is_func_ptr(address):
        funcaddr = VtableFunction.funcaddr(address)
        return is_code(funcaddr)


class NameSanitizer:
    symbol_replacer = [
        ['*', '_'],
        ['(', '_'],
        [')', '_'],
        ['&', '_'],
        [' ', '_'],
        ['<', '_'],
        ['>', '_'],
        ['-', '_'],
        [':', '_'],
        ['.', '_'],
        ['[', '_'],
        [']', '_'],
    ]

    @staticmethod
    def sanitize_name(name):
        sanitized_name = name
        for r in NameSanitizer.symbol_replacer:
            sanitized_name = sanitized_name.replace(r[0], r[1])
        return sanitized_name.strip('_')


class Vtable:
    def __init__(self, hierarchy, name, address) -> None:
        self.name = name
        self.address = address
        self.functions = self._scan_vtable()
        self.address_end = self.address + len(self.functions) * 8 + 0x10
        self.hierarchy = hierarchy

    def _scan_vtable(self):
        functions = []
        # skip 0x10 bytes at beggining because they are zeores
        address = self.address + 0x10
        offset = 0
        value_at_address = ida_bytes.get_original_qword(address)
        while value_at_address and VtableFunction.is_func_ptr(address):
            functions.append(VtableFunction(self, address, offset))
            address += 8
            offset += 8
            value_at_address = ida_bytes.get_original_qword(address)
        return functions

    def is_function_part_of_vtable(self, function_address):
        for func in self.functions:
            if function_address == func.function_address:
                return True
        return False

    def sanitize_name_struct_vtable(self):
        return f'{self.sanitize_name()}_vtbl'

    def sanitize_name(self):
        return NameSanitizer.sanitize_name(self.name)

    def apply_name(self):
        idc.set_name(self.address, f'vtable_for_{self.sanitize_name()}')

    def is_address_part_of_vtable(self, address):
        return self.address < address < self.address_end

    def __repr__(self) -> str:
        funcs = f''
        for func in self.functions:
            funcs += f'  {func}\n'
        final = f'''vtable for'{self.name} :\n'''
        final += funcs
        return final

    def rename_functions(self):
        for func in self.functions:
            func.rename_function()

    def create_vtable_struct(self):
        tid = idc.add_struc(idc.BADADDR, self.sanitize_name_struct_vtable(), False)
        if tid == idc.BADADDR:
            return False

        for func in self.functions:
            idc.add_struc_member(tid, func.function_name(), func.offset, idc.FF_QWORD, -1, 8)

    def fix_vtable_struct(self, tid):
        for func in self.functions:
            idc.set_member_name(tid, func.offset, func.function_name())

    def update_vtable_struct(self):
        tid = idc.get_struc_id(self.sanitize_name_struct_vtable())
        if tid == idc.BADADDR:
            self.create_vtable_struct()
        else:
            self.fix_vtable_struct(tid)

    @staticmethod
    def is_vtable(address):
        return Vtable.check_is_signed_with_pac_key(address, 0xCDA1)

    @staticmethod
    def check_is_signed_with_pac_key(addr, pac):
        xrefs = idautils.XrefsTo(addr)
        for xref in xrefs:
            req_addr = xref.frm

            if ida_ua.print_insn_mnem(req_addr) == 'ADRL':
                if idc.get_operand_type(req_addr, 0) == ida_ua.o_reg and idc.get_operand_value(req_addr, 0) == 0x91:
                    max_step = 5
                    while max_step:
                        req_addr += 4
                        if ida_ua.print_insn_mnem(req_addr) == 'MOVK':
                            if idc.get_operand_type(req_addr, 0) == ida_ua.o_reg and idc.get_operand_value(req_addr, 0) == 0x92:
                                if idc.get_operand_value(req_addr, 1) == pac:
                                    return True
                        max_step -= 1
        return False


def collect_kalloc_types(seen: Array) -> Dict:
    kalloc_types = {}
    for segaddr in idautils.Segments():
        if '__kalloc_type' not in idc.get_segm_name(segaddr):
            continue

        seg = ida_segment.getseg(segaddr)
        curr_addr = seg.start_ea
        seg_end = seg.end_ea
        while curr_addr < seg_end:
            if ida_bytes.get_qword(curr_addr + 0x10) != 0:
                next_kt = KallocType.parse(curr_addr)
                if next_kt.name not in kalloc_types.keys() and next_kt.name not in seen and next_kt.sanitized_name not in KallocType.skip_names:
                    kalloc_types[next_kt.name] = next_kt
            curr_addr += 0x40

    return kalloc_types


class KallocType:
    skip_names = [
        'T',
        'tExpansionData',
    ]

    def __init__(self, address, driver_name, name, flag, size) -> None:
        self.address = address
        self.driver_name = driver_name
        self.name = name
        self.flag = flag
        self.size = size
        self.sanitized_name = self.sanitize_name()

    def sanitize_name(self):
        return NameSanitizer.sanitize_name(self.name)

    def get_class_declaration(self):
        s = None
        start = 0
        end = self.size

        is_packed = end % 8
        s =  f'struct {'__attribute__((packed))' if is_packed else ''} {self.sanitized_name} {chr(0x7b)}\n'

        while start < end:
            still = end-start
            if still == 1:
                s += f'    __int8 field_{start:x};\n'
                start += 2
            elif still == 2:
                s += f'    __int16 field_{start:x};\n'
                start += 2
            elif 2 < still <= 8:
                s += f'    __int32 field_{start:x};\n'
                start += 4
            else:
                s += f'    __int64 field_{start:x};\n'
                start += 8

        s += '};\n'
        return s

    def create_structure(self):
        tid = idc.get_struc_id(self.sanitized_name)
        if tid == idc.BADADDR:
            create_struct(self.get_class_declaration())

    @staticmethod
    def parse(address) -> KallocType:
        segname = idc.get_segm_name(address)
        driver_name = segname.split(':')[0]
        name_offset = 0x10 + address
        typ_offset  = 0x20 + address
        flag_offset = 0x28 + address
        size_offset = 0x2c + address
        name = ida_bytes.get_strlit_contents(ida_bytes.get_qword(name_offset), idc.BADADDR, ida_nalt.STRTYPE_C).decode()
        name = name.split('site.')[1]
        # typ = ''
        # if ida_bytes.get_byte(get_qword(typ_offset)) != 0x0:
        #     typ = ida_bytes.get_strlit_contents(ida_bytes.get_qword(typ_offset), idc.BADADDR, ida_nalt.STRTYPE_C).decode()
        flag = ida_bytes.get_dword(flag_offset)
        size = ida_bytes.get_dword(size_offset)
        # if 'struct' not in name and 'typeof' not in name:
        # if '>' in name:
        #     print(f'{addr:016x} {name:60s} : 0x{flag:08x} : 0x{size:08x}')
        return KallocType(address, driver_name, name, flag, size)


def save_metaclass_info(init_calls: list[OSMetaClassConstructorCall], filename):
    with open(filename, 'w') as fd:
        for call in init_calls:
            fd.write(f'{call}\n')


def load_metaclass_info(filename):
    emulated_info = []
    lines = open(filename, 'r').read().split('\n')
    for line in lines:
        if line == '':
            continue
        emulated_info.append(OSMetaClassConstructorCall.parse_string(line))
    return emulated_info


hier = None
kts = None
platform = None

def get_platform():
    global platform

    MH_MAGIC_64      = 0xfeedfacf
    LC_BUILD_VERSION = 0x32

    if platform is not None:
        return platform

    seg_header = ida_segment.get_segm_by_name('com.apple.kernel:HEADER')
    header = seg_header.start_ea
    magic = ida_bytes.get_dword(header)
    if magic != MH_MAGIC_64:
        print(f'[-] Wrong header')

    cput        = ida_bytes.get_dword(header+4)
    cpusub      = ida_bytes.get_dword(header+8)
    filetype    = ida_bytes.get_dword(header+12)
    ncmds       = ida_bytes.get_dword(header+16)
    sizeofcmds  = ida_bytes.get_dword(header+20)
    flags       = ida_bytes.get_dword(header+24)
    reserved    = ida_bytes.get_dword(header+28)

    offset = 32
    for idx in range(ncmds):
        if offset > seg_header.end_ea - header:
            break

        cmd     = ida_bytes.get_dword(header+offset)
        cmdsize = ida_bytes.get_dword(header+offset+4)

        if cmd == LC_BUILD_VERSION:
            platform = ida_bytes.get_dword(header+offset+8)
            return platform

        offset += cmdsize

    return None


def run():
    os.chdir(os.path.dirname(idc.get_idb_path()))
    main()


MACOS = 0x1
IOS   = 0x2


def main():
    global hier
    global kts

    platform = get_platform()

    if platform == IOS:
        ida_typeinf.del_til('xnu_7195_arm64')

    emulated_info = None
    if os.access('metaclass_info.txt', 644):
        emulated_info = load_metaclass_info('metaclass_info.txt')
    else:
        emulated_info = emulate_all_OSMetaClass_constructors()
        print(f'Found OSMetaClass by emulating => {len(emulated_info)}')
        save_metaclass_info(emulated_info, 'metaclass_info.txt')

    if platform == IOS:
        apply_names(emulated_info)
    find_vtables_via_FFFC(emulated_info)

    hier = Hierarchy(emulated_info)
    if platform == IOS:
        hier.apply_names()
        hier.rename_functions()
        hier.update_vtables()
    hier.create_structures()

    for cl in hier.hierarchy.keys():
        if hier.hierarchy[cl]['vtable'] is None:
            print(f'[!] {cl:20s}')

    kts = collect_kalloc_types(hier.hierarchy.keys())
    for k in kts.keys():
        kts[k].create_structure()
        # print(f'{kts[k].address:x} {kts[k].sanitized_name:60s} {k}')

if __name__ == '__main__':
    main()
