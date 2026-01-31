import idc
import idautils
import idaapi
import pprint
import ida_bytes
import sys
from idaemu import *
from dataclasses import dataclass, field

MAGIC_RET = 0x4141414140

is_new_called = False

new_param = []

driver_name = ''
class_name_caller = ''

bad_driver = []
bad_allocs = []
done = False
static_calls_of_osmetaclass = 0
dynamic_calls_of_osmetaclass = 0

alloc_calls = {}


class myEmu_stage_alloc(Emu):
    def __init__(self, stack=0xf000000, ssize=3):
        super(myEmu_stage_alloc, self).__init__(stack, ssize)

    def _hook_mem_invalid(self, uc, access, address, size, value, user_data):
        addr = self._alignAddr(address)
        uc.mem_map(addr, PAGE_ALIGN)
        data = self._getOriginData(addr, PAGE_ALIGN)
        uc.mem_write(addr, data)
        # print("MEM INVALID ADDRESS: 0x%016X" % (address))
        # print(access)
        # print(value)
        return True

    def _hook_mem_access(self, uc, access, address, size, value, user_data):
        global is_new_called
        global new_param

        if access == UC_MEM_WRITE and is_new_called == True and MAGIC_RET == address:
            is_new_called = False
            PC = uc.reg_read(UC_ARM64_REG_PC)
            Op0 = GetOpnd(PC, 0)
            # print("PC -> " + hex(PC))
            # print("Op0 -> " + Op0)
            reg = 0
            exec("reg = UC_ARM64_REG_" + Op0)
            value = uc.reg_read(reg)
            # print("Address -> " + hex(address))
            # print("Value   -> " + str(value))
            if MAGIC_RET == address and (value & 0xfffffff000000000) == 0xfffffff000000000:
                new_param.append(value)
                if class_name_caller not in alloc_calls.keys():
                    alloc_calls[class_name_caller] = []
                alloc_calls[class_name_caller].append(new_param)
                new_param = []
            else:
                print("MAGIC_RET => " + hex(address))
                print("VALUE     => " + hex(value))
                print("Op0       => " + Op0)
                print("PC        => " + hex(PC))
                print("ERRRRRRRRRRRRRRRRRRRRORRRRRRRRRRRR")
                is_new_called = True
        elif access == UC_MEM_WRITE and self.traceOption & TRACE_DATA_WRITE:
            self._addTrace("### Memory WRITE at 0x%x, data size = %u, data value = 0x%x" \
                           % (address, size, value))
        elif access == UC_MEM_READ and self.traceOption & TRACE_DATA_READ:
            self._addTrace("### Memory READ at 0x%x, data size = %u" \
                           % (address, size))

def my_new(uc, out, args):
    global is_new_called
    global new_param
    new_param = []

    is_new_called = True
    # print("  Params:")
    for i in args:
        new_param.append(i)
        # print("     " + str(i))

    return MAGIC_RET


def my_stub(uc, out, args):
    return 0x0


def my_stub_new(uc,out,args):
    return MAGIC_RET


def emulate_alloc(func_addr, function_end_addr, new_addr, addresses):
    a = myEmu_stage_alloc(UC_ARCH_ARM64, UC_MODE_ARM)
    a.alt(new_addr, my_new, 2, False)
    a.setTrace(TRACE_DATA_WRITE)
    a.setTrace(TRACE_CODE)
    for addr in addresses:
        a.alt(addr, my_stub_new, 0, False)

    a._emulate(func_addr, function_end_addr, [], 1000000)

    return a
    # print("----- Start emu -----")
    # a.showTrace()


def get_address_of_new(addr):
    start_addr = addr
    end_addr = idc.get_func_attr(addr, FUNCATTR_END)
    curr_addr = start_addr
    while curr_addr < end_addr-4:
        if ida_ua.print_insn_mnem(curr_addr) == 'BL':
            op = GetOpnd(curr_addr, 0)
            if '__ZN8OSObjectnwEm' in op:
                return(LocByName(op))
        curr_addr += 4
    return None


def parse_alloc_function(addr):
    """
    Function parses allocation function in OSMetaClass class.
    Return:
      1. Emultaion start address
      2. Emulation end address
      3. Addresses for hooks due to emulation
    """
    start_addr = addr
    cur_addr = start_addr
    end_addr = idc.get_func_attr(addr, FUNCATTR_END)

    # Substract because of idc.get_func_attr return
    # address of next DWORD after end
    end_addr -= 4

    hooks = []

    while cur_addr <= end_addr:
        mnem = ida_ua.print_insn_mnem(cur_addr)
        op = GetOpnd(cur_addr, 0)
        if mnem == 'BL':
            if '__ZN8OSObjectnwEm' in op:
                # We must to skip calls to new function
                # because it will be emulated and returned our MAGIC_RET
                pass
            else:
                # Add call function to hooks array
                hooks.append(LocByName(op))

        elif mnem == 'B' and cur_addr == end_addr:
            # If end of function jumps to another function
            # then it is THUNK function.
            # Update `cur_addr`, `end_addr` and parse next function
            cur_addr = LocByName(op)
            end_addr = idc.get_func_attr(cur_addr, FUNCATTR_END)
            continue

        cur_addr += 4

    return start_addr,end_addr,hooks


def add_struct_to_idb(name):
    idc.Til2Idb(-1, name)


def parse_demangled_name(str):
    class_name = str[0:str.find(':')]
    func_name = str[str.find(':')+2:str.find('(')]
    return [class_name,func_name]


def create_vtable_struct(class_name, functions):
    struct_name = 'VTABLE_' + class_name
    sid = idc.GetStrucIdByName(struct_name)
    if sid != BADADDR:
        print("vtable already exists for " + class_name)
        return False

    sid = idc.AddStrucEx(-1, struct_name, 0)
    # idc.Til2Idb(-1, struct_name)

    offset = 0
    for fn in functions:
        func_name = fn[0]
        func_name = func_name.replace('~', 'destr_')
        func_type = fn[1]

        ret = add_struc_member(sid, func_name, -1, idc.FF_QWORD, -1, 8)
        # Ohhhh name name..
        # i=0
        if ret == -1:
            print("error creating struct VTABLE: %s (%d) (%s)" % (class_name, ret, func_name))
            return False

        if func_type != '':
            if func_type.find("__cdecl(") > -1:
                func_type = func_type.replace("__cdecl", "(__cdecl *%s)" % func_name)
            elif func_type.find("__stdcall(") > -1:
                func_type = func_type.replace("__stdcall", "(__stdcall *%s)" % func_name)
            elif func_type.find("__fastcall(") > -1:
                func_type = func_type.replace("__fastcall", "(__fastcall *%s)" % func_name)
            elif func_type.find("__thiscall(") > -1:
                func_type = func_type.replace("__thiscall", "(__thiscall *%s)" % func_name)
            elif func_type.find("__usercall(") > -1:
                func_type = func_type.replace("__usercall", "(__usercall *%s)" % func_name)
            elif func_type.find("__userpurge(") > -1:
                func_type = func_type.replace("__userpurge", "(__userpurge *%s)" % func_name)

            SetType(GetMemberId(sid, offset), func_type)
            # MakeComm(GetMemberId(sid, offset), func_name)
            # "__int64 (__fastcall *)(ClassName *this)");
        offset += 8
        # print(fn)

    return True


def calc_element_size(pos, end):
    if end-pos >= 8:
        return 8
    elif end-pos >= 4:
        return 4
    elif end-pos >= 2:
        return 2
    elif end-pos == 1:
        return 1
    else:
        return 0


def create_class_struct(class_name, size):
    struct_name = 'CLASS_' + class_name + '_%0X'%(size)
    sid = idc.GetStrucIdByName(struct_name)
    if sid != BADADDR:
        print("class already exists for " + class_name)
        return False

    sid = add_struc(-1, struct_name, 0)
    # idc.Til2Idb(-1, struct_name)

    # Add vtable member
    ret = add_struc_member(sid, name='vtable', offset=-1, flag=FF_QWORD, typeid=-1, nbytes=8)
    if ret != 0:
        print("error creating struct CLASS: %s (%d) " % (class_name,ret))
        return False

    # Fill class by elements until end
    # pos = 8
    # end = size

    # flags = {
    #     1: FF_BYTE,
    #     2: FF_WORD,
    #     4: FF_DWORD,
    #     8: FF_QWORD
    # }

    # Skip creating very big structures
    # if size > 4096:
    #     return True

    # while pos < end:
    #     element_size = calc_element_size(pos,end)
    #     if add_struc_member(sid, name='element_%x'%pos, offset=-1, flag=flags[element_size], typeid=-1, nbytes=element_size) != 0:
    #         print("error while fill struct in class " + class_name)
    #         return False
    #     pos += element_size

    return True


def reconstruct_vtable(vtable_addr, current_class_name):
    vtable_addr_local = vtable_addr
    func = ida_bytes.get_qword(vtable_addr_local)
    vtable_functions = []
    used_function_names = []

    while func != 0 and (func&0xfffffff000000000)==0xfffffff000000000 and '__text' in SegName(func):
        # print("  Address = " + hex(func))

        # func_addr = idc.get_func_attr(func, FUNCATTR_START)
        # MakeCode(func)

        # if add_func(func) != 0:
        #     return False, []
        if idc.is_code(func) == False:
            MakeUnknown(ida_bytes.get_qword(vtable_addr_local), 1, idaapi.DOUNK_SIMPLE)
            # idaapi.autoWait()
            # if fptr != ida_bytes.get_qword(class_vtable + i * 8):
            #     print("BBBBBBBBBBBBBBBBBBBBBBB")
            # fptr = ida_bytes.get_qword(class_vtable + i * 8)
            MakeCode(ida_bytes.get_qword(vtable_addr_local))
            idaapi.autoWait()
        # MakeCode(func)
        # idaapi.autoWait()
        MakeFunction(ida_bytes.get_qword(vtable_addr_local))
        idaapi.autoWait()
        OpOff(vtable_addr_local, 0, 0)
        idaapi.autoWait()
        # func_name = GetFunctionName(func)
        # if func_name == '':
        func_name = NameEx(BADADDR, func)
        if func_name == '':
            func_name = 'sub_' + '%016X' % func
            print("  NNMNNMNNMNNMNNM => 0x%016x" % (func))
            #func_name = 'unnamed_function'
            # print("No name :( " + hex(vtable_addr_local))
            # sys.exit(0)

        if func_name[0:3] == 'loc':
            print("  LOCLOCLOCLOCLOC => %s" % (func_name))
            if idc.get_func_attr(func, FUNCATTR_START) not in (func, idc.BADADDR):
                mainfunc = idc.get_func_attr(func, FUNCATTR_START)
                print("  SEPARATE FUNCTION => 0x%016x" % (mainfunc))
                MakeUnknown(mainfunc, 1, idaapi.DOUNK_SIMPLE)
                idaapi.autoWait()
                MakeCode(ida_bytes.get_qword(vtable_addr_local))
                idaapi.autoWait()
                MakeFunction(ida_bytes.get_qword(vtable_addr_local))
                idaapi.autoWait()
                MakeCode(mainfunc)
                if MakeFunction(mainfunc):
                    idaapi.autoWait()
                else:
                    print("  NOT RECONSTRUCT => 0x%016x" % (mainfunc))
            else:
                if MakeFunction(ida_bytes.get_qword(vtable_addr_local)):
                    idaapi.autoWait()
                else:
                    print("  NOT RECONSTRUCT => 0x%016x" % (ida_bytes.get_qword(vtable_addr_local)))

            func_name = func_name.replace('loc','sub')
        elif func_name[0:3] == 'unk':
            print("  SUBSUBSUBSUBSUB => %s" % (func_name))
            func_name = func_name.replace('unk','sub')
            #     func_name = 'unnamed_function'
            #     print("No name :( " + hex(func))
            #     sys.exit(0)
            #
            # func_name = get_name(func)
            # if 'off' in func_name:
            #     func_name = func_name.replace('off', 'sub')
            # elif 'loc' in func_name:
            #     func_name = func_name.replace('loc', 'sub')
            # lif 'unk' in func_name:
            #     func_name = func_name.replace('unk', 'sub')


        func_type = GetType(func)

        if func_type == None:
            func_type = '__int64 __fastcall()'

        if func_name[0:3] == '__Z':
            func_name = Demangle(func_name,0)
            class_name, func_name = parse_demangled_name(func_name)

            if class_name != current_class_name:
                func_name = class_name + '::' + func_name

        new_func = func_name
        i=0
        while new_func in used_function_names:
            new_func = func_name + '_' + str(i)
            i+=1

        vtable_functions.append([new_func, func_type])
        used_function_names.append(new_func)

        # OpOff(vtable_addr_local, 0, 0)
        vtable_addr_local += 8
        func = ida_bytes.get_qword(vtable_addr_local)

    return True, vtable_functions


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

def atk(addr):
    return hex(addr)

OSMETACLASS_CONSTRUCTOR_ADDR = idc.get_name_ea_simple('__ZN11OSMetaClassC2EPKcPKS_j')

class EmulationWrong(Exception):
    def __inti__(self, static, dynamic):
        self.dynamic = dynamic
        self.static = static
        super().__init__(f"Dynamic != Static ({dynamic} / {static})")


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
            self.alt(addr, my_stub, 0, False)

        self._emulate(self.start, self.end, [], 1000000)

        # print("----- Start emu -----")
        # self.showTrace()

def emulate_all_OSMetaClass_constructors():
    # Reconstruct parameters for call's to OSMetaClass::OSMetaClass
    OSMetaClass_calls = {}

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
            # if driver_name == 'com.apple.kernel':
            #     continue
            print(f"    Count Init funcs -> {count_init_function}")
            if driver_name not in OSMetaClass_calls.keys():
                OSMetaClass_calls[driver_name] = []
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
                    OSMetaClass_calls[driver_name].append(emulator.calls[k])

                start_addr += 8

    return OSMetaClass_calls


def get_class(init_calls: list[OSMetaClassConstructorCall], osmetaclass):
    print(hex(osmetaclass))
    for call in init_calls:
        if call.osmetaclass == osmetaclass:
            return call
    return None


def apply_names(init_calls: list[OSMetaClassConstructorCall]):
    # Rename all gMetaClass pointers and vtable pointers

    for call in init_calls:
        # "__ZN24IODARTVMAllocatorGeneric10gMetaClassE_0"
        # "__ZTVN19H11ANEInVMAllocator9MetaClassE
        class_name = call.get_name()
        if '<' in class_name:
            continue

        class_name_meta = f'__ZN{len(class_name)}{class_name}10gMetaClassE_0'
        class_vtable_name = f'__ZTVN{len(class_name)}{class_name}9MetaClassE'

        idc.set_name(call.osmetaclass, class_name_meta)
        idc.set_name(call.vtable-0x10, class_vtable_name)


def dump_classes(init_calls: list[OSMetaClassConstructorCall]):
    with open('classes_iphone.txt', 'w') as fd:
        for call in init_calls:
            class_ptr = call.osmetaclass
            class_name = call.get_name()

            print(f'class_name : {class_name}')

            if class_name == 'OSMetaClass' or class_name == 'OSObject':
                continue

            print(call)
            class_parent = get_class(init_calls, call.parent)
            class_parent_name = class_parent.get_name()

            fd.write(f'class {class_name}: public {class_parent_name}\n')

# init_calls = None

def main():
    # global init_calls
    # init_calls = emulate_all_OSMetaClass_constructors()
    count_OSMetaClass_emul = 0
    for i in init_calls.keys():
        count_OSMetaClass_emul += len(init_calls[i])

    print("Found OSMetaClass by emulating => " + str(count_OSMetaClass_emul))
    print(init_calls["com.apple.iokit.IOGPUFamily"])

    linear_init_calls = []
    for drv in init_calls.keys():
        linear_init_calls.extend(init_calls[drv])

    # apply_names(linear_init_calls)
    idc.auto_wait()
    dump_classes(linear_init_calls)
    # print(bad_driver)

if __name__ == '__main__':
    main()


# # Find alloc functions and emulate
# for drv in init_calls.keys():
#     for call in init_calls[drv]:
#         # OpOff(class_gmeta_vtable_ptr + 12*8,0,0)
#         class_name_caller = GetString(call[1])
#         class_gmeta_vtable_ptr = call[4]
#         class_gmeta_alloc_func = ida_bytes.get_qword(class_gmeta_vtable_ptr + 12*8)
#         print("EMUL ALLOC -> " + class_name_caller + " " + hex(class_gmeta_vtable_ptr) + ' ' + hex(class_gmeta_alloc_func))

#         if class_gmeta_alloc_func != 0:
#             function_addr = class_gmeta_alloc_func
#             # function_end_addr = idc.get_func_attr(function_addr, FUNCATTR_END)

#             # WTF: idc.get_func_attr(function_addr, FUNCATTR_END) RETURN addr of next function
#             # if function_end_addr != BADADDR:
#             #     function_end_addr -= 4

#             new_addr = get_address_of_new(function_addr)
#             if new_addr == None:
#                 continue

#             function_addr, function_end_addr, addresses = parse_alloc_function(function_addr)
#             # print(addresses)
#             # print(hex(new_addr))
#             # print(hex(function_addr))
#             # print(hex(function_end_addr))
#             MakeNameEx(function_addr, class_name_caller + '::alloc', 0)
#             a = emulate_alloc(function_addr, function_end_addr, new_addr, addresses)
#             if is_new_called == True:
#                 bad_allocs.append({'function': function_addr, 'class_name': class_name_caller})
#                 print("EEEEEEEEERRRRRRRRRRRRRRRRRRROOOOOOOOOOOOOORRRRRRRRRRRRRRRRRRRRRRRRRRRRR")
#                 print("  * Start: 0x%016X" % function_addr)
#                 print("  * End:   0x%016X" % function_end_addr)
#                 print("  * Hooks:")
#                 print(addresses)
#                 a.showTrace()
#                 is_new_called = False

# bad_creation = []

# # a = fuck

# for cls in alloc_calls.keys():
#     # print("")
#     # print(cls)

#     # for call in alloc_calls[cls]:
#     #     del_struc(get_struc_id('VTABLE_'+cls))
#     #     del_struc(get_struc_id('CLASS_'+cls+'_%X'%call[0]))


#     for call in alloc_calls[cls]:
#         size = call[0]
#         ppp = call[1]
#         vtable = call[2]
#         print(cls + ': ('+hex(size)+', ' + hex(ppp) + ') = ' + hex(vtable))
#         MakeNameEx(vtable, 'vtbl_' + cls, 0)

#         # Create struct CLASS_ClassName_HEXSIZE
#         struct_was_created = create_class_struct(cls, size)

#         # Reconstruct functions list for creating VTABLE_ClassName
#         vtable_was_reconstruct, vtable_functions = reconstruct_vtable(vtable, cls)

#         # Create struct VTABLE_ClassName
#         vtable_was_created = False
#         if vtable_was_reconstruct:
#             vtable_was_created = create_vtable_struct(cls, vtable_functions)

#         if vtable_was_created and struct_was_created:
#             msid = get_struc_id('VTABLE_'+cls)
#             ssid = get_struc_id('CLASS_'+cls+'_%X' % size)
#             # et_member_type(ssid, 0, FF_0STRO, msid, 1)
#             SetType(get_member_id(ssid, 0), 'struct VTABLE_' + cls + ' *')
#             SetType(vtable, 'struct VTABLE_' + cls)

#         else:
#             bad_creation.append(cls)



# print("[!] STAGE EMULATION INIT ERRORS:")
# pprint.pprint(bad_driver)
# print("[!] STAGE EMULATION ALLOC ERRORS:")
# pprint.pprint(bad_allocs)
# print("[i] STAGE CREATION classes and/or vtables ERROR:")
# pprint.pprint(bad_creation)
