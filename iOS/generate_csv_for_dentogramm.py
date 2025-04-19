import idc
import ida_bytes
from idaemu import *
from dataclasses import dataclass, field

OSMETACLASS_CONSTRUCTOR_ADDR = idc.get_name_ea_simple('__ZN11OSMetaClassC2EPKcPKS_j')

def atk(addr):
    return hex(addr)

class EmulationWrong(Exception):
    def __inti__(self, static, dynamic):
        self.dynamic = dynamic
        self.static = static
        super().__init__(f"Dynamic != Static ({dynamic} / {static})")

class OSMetaClassConstructorCall():
    def __init__(self, osmetaclass, name, parent, size):
        self.osmetaclass = osmetaclass
        self.name        = name
        self.parent      = parent
        self.size        = size
        self.vtable      = None

    def get_name(self):
        return ida_bytes.get_strlit_contents(self.name, BADADDR, ida_nalt.STRTYPE_C).decode()

    def __repr__(self):
        return f'OSMetaClass::OSMetaClass({hex(self.osmetaclass)}, "{self.get_name()}", {hex(self.parent)}, {hex(self.size)})'

class myEmu_stage_init(Emu):
    def __init__(self, start_ea, stack=0xf000100, ssize=3):
        super(myEmu_stage_init, self).__init__(stack, ssize)
        self.start = start_ea
        self.end = idc.get_func_attr(start_ea, FUNCATTR_END) - 4
        self.hooks = []
        self.calls = {}
        self.found_OSMetaClass_calls = 0
        self.static_calls_of_osmetaclass = 0
        self.dynamic_calls_of_osmetaclass = 0
        self.scan_func()

    def _hook_mem_invalid(self, uc, access, address, size, value, user_data):
        addr = self._alignAddr(address)
        uc.mem_map(addr, PAGE_ALIGN)
        data = self._getOriginData(addr, PAGE_ALIGN)
        uc.mem_write(addr, data)
        # print("MEM INVALID ADDRESS: 0x%016X" % (address))
        # print(access)
        # print("MEM INVALID VALUE:   0x%016X" % (value))
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
        if access == UC_MEM_WRITE and atk(address) in self.calls.keys():

            # Get a register through idapython
            PC = uc.reg_read(UC_ARM64_REG_PC)
            Op0 = self.get_op_regnum(PC)

            # Get a register from first operand
            reg = self.op_regnum_to_unicorn(Op0)

            # Read vtable from that register
            vtable = uc.reg_read(reg)

            # print(f"MAGIC_RET => {hex(address)}")
            # print(f"VALUE     => {hex(vtable)}")
            # print(f"Op0       => {Op0}")
            # print(f"PC        => {hex(PC)}")

            self.calls[atk(address)].vtable = vtable
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
            if OSMETACLASS_CONSTRUCTOR_ADDR == self.get_BL_addr(addr):
                return True
        return False

    def is_success(self):
        return self.static_calls_of_osmetaclass == self.dynamic_calls_of_osmetaclass

    def info(self):
        print(f"        Func -> {hex(function_addr)}")
        print(f"        Found calls osmetaclass by emulate -> {emulator.dynamic_calls_of_osmetaclass}")
        if emulator.dynamic_calls_of_osmetaclass != emulator.static_calls_of_osmetaclass:
            print(f"        Found calls osmetaclass by static -> {emulator.static_calls_of_osmetaclass} !")
        else:
            print(f"        Found calls osmetaclass by static -> {emulator.static_calls_of_osmetaclass}")

    def my_stub(self, uc, out, args):
        return 0x0

    def hook_OSMetaClass_contructor(self, uc, out, args):
        osmetaclass = args[0]
        name        = args[1]
        parent      = args[2]
        size        = args[3]

        if atk(osmetaclass) in self.calls.keys():
            raise

        self.calls[atk(osmetaclass)] = OSMetaClassConstructorCall(osmetaclass, name, parent, size)
        return osmetaclass

    def scan_func(self):
        cur_addr = self.start
        while cur_addr <= self.end:
            if self.is_BL_insn(cur_addr):
                if self.is_call_osmetaclass_contructor(cur_addr):
                    self.static_calls_of_osmetaclass += 1
                else:
                    self.hooks.append(self.get_BL_addr(cur_addr))
            cur_addr += 4

    def emulate(self):
        self._createUc()

        self.alt(OSMETACLASS_CONSTRUCTOR_ADDR, self.hook_OSMetaClass_contructor, 4, False)
        self.setTrace(TRACE_DATA_WRITE)
        self.setTrace(TRACE_CODE)
        for addr in self.hooks:
            self.alt(addr, self.my_stub, 0, False)

        self._emulate(self.start, self.end, [], 1000000)
        # print("----- Start emu -----")
        # self.showTrace()


def emulate_all_OSMetaClass_constructors():
    # Reconstruct parameters for call's to OSMetaClass::OSMetaClass
    OSMetaClass_calls = []

    for seg_ea in Segments():
        if '__mod_init_func' in get_segm_name(seg_ea):
            seg = ida_segment.getseg(seg_ea)
            name = get_segm_name(seg_ea)
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
    # Rename all gMetaClass pointers and vtable pointers

    for call in init_calls:
        class_name = call.get_name()
        if '<' in class_name:
            continue

        class_name_meta = f'__ZN{len(class_name)}{class_name}10gMetaClassE_0'
        class_vtable_name = f'__ZTVN{len(class_name)}{class_name}9MetaClassE'

        idc.set_name(call.osmetaclass, class_name_meta)
        idc.set_name(call.vtable-0x10, class_vtable_name)


def dump_classes(init_calls: list[OSMetaClassConstructorCall], filename):
    with open(filename, 'w') as fd:
        for call in init_calls:
            class_name = call.get_name()

            if class_name == 'OSMetaClass' or class_name == 'OSObject':
                continue

            class_parent = get_class(init_calls, call.parent)
            class_parent_name = class_parent.get_name()

            fd.write(f'class {class_name}: public {class_parent_name}\n')


class CSVConverter():
    def __init__(self, input, output):
        self.input = input
        self.output = output
        self.parents = {}

    def get_class(self, line):
        a1 = line.split(':')[0]
        a1 = a1.strip(' ')
        return a1.split(' ')[-1]

    def get_parent(self, line):
        a1 = line.strip('\n')
        a1 = a1.strip(' ')
        return a1.split(' ')[-1]

    def create_children_node(self, node):
        result = []

        if node in self.parents.keys():
            result.append(node + ',')
            for chld in self.parents[node]:
                ret = self.create_children_node(chld)
                for i in ret:
                    result.append(node + '.' + i)
        else:
            result.append(node + ',0')

        return result

    def convert(self):
        with open(self.input, 'r') as fdr:
            line = fdr.readline()
            while line:
                node = self.get_class(line)
                parent = self.get_parent(line)
                print(node + ' -> ' + parent)

                if parent not in self.parents.keys():
                    self.parents[parent] = []

                self.parents[parent].append(node)

                line = fdr.readline()

        head = "OSObject"
        output = self.create_children_node(head)

        with open(self.output, 'w') as fd:
            fd.write('id,value\n')
            for i in output:
                fd.write(i + '\n')


def main():
    init_calls = emulate_all_OSMetaClass_constructors()

    print(f'Found OSMetaClass by emulating => {len(init_calls)}')

    # apply_names(init_calls)
    idc.auto_wait()
    dump_classes(init_calls, 'classes.txt')
    converter = CSVConverter('classes.txt', 'iokit.csv')
    converter.convert()


if __name__ == '__main__':
    main()
