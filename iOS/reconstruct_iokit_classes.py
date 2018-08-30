import idc
import idautils
import idaapi
import pprint
import sys
from idaemu import *

MAGIC_RET = 0x4141414140

is_OSMetaClass_called = False
is_new_called = False

OSMetaClass_param = []
new_param = []

driver_name = ''
class_name_caller = ''

bad_driver = []
bad_allocs = []
done = False
static_calls_of_osmetaclass = 0
count_OSMetaClass_parsing = 0
dynamic_calls_of_osmetaclass = 0

init_calls = {}
alloc_calls = {}


class myEmu_stage_init(Emu):
    def __init__(self, arch, mode, compiler=COMPILE_GCC, stack=0xf000100,ssize=3):
        super(myEmu_stage_init, self).__init__(arch, mode, compiler, stack,ssize)

    def _hook_mem_invalid(self, uc, access, address, size, value, user_data):
        addr = self._alignAddr(address)
        uc.mem_map(addr, PAGE_ALIGN)
        data = self._getOriginData(addr, PAGE_ALIGN)
        uc.mem_write(addr, data)
        # print("MEM INVALID ADDRESS: 0x%016X" % (address))
        # print(access)
        # print("MEM INVALID VALUE:   0x%016X" % (value))
        return True

    def _hook_mem_access(self, uc, access, address, size, value, user_data):
        global is_OSMetaClass_called
        global OSMetaClass_param
        global dynamic_calls_of_osmetaclass
        
        if access == UC_MEM_WRITE and is_OSMetaClass_called == True: #self.traceOption & TRACE_DATA_WRITE:
            is_OSMetaClass_called = False

            # Sometimes doesn't work
            # X8 = uc.reg_read(UC_ARM64_REG_X8)
            # X0 = uc.reg_read(UC_ARM64_REG_X0)
            # print(hex(X8))
            # print(hex(X0))

            # Get a register through idapython
            PC = uc.reg_read(UC_ARM64_REG_PC)
            Op0 = GetOpnd(PC, 0)

            # Get a register from first operand
            reg = 0
            exec("reg = UC_ARM64_REG_" + Op0)

            # Read value from that register
            value = uc.reg_read(reg)

            if address == MAGIC_RET or address == OSMetaClass_param[0]:
                OSMetaClass_param.append(value)
                if driver_name not in init_calls.keys():
                    init_calls[driver_name] = []
                init_calls[driver_name].append(OSMetaClass_param)
                dynamic_calls_of_osmetaclass += 1
                # print(OSMetaClass_param)
                OSMetaClass_param = []
            else:
                print("MAGIC_RET => " + hex(address))
                print("VALUE     => " + hex(value))
                print("Op0       => " + Op0)
                print("PC        => " + hex(PC))
                print("ERRRRRRRRRRRRRRRRRRRRORRRRRRRRRRRR")
        elif access == UC_MEM_WRITE and self.traceOption & TRACE_DATA_WRITE:
            self._addTrace("### Memory WRITE at 0x%x, data size = %u, data value = 0x%x" \
                           % (address, size, value))
        elif access == UC_MEM_READ and self.traceOption & TRACE_DATA_READ:
            self._addTrace("### Memory READ at 0x%x, data size = %u" \
                           % (address, size))


class myEmu_stage_alloc(Emu):
    def __init__(self, arch, mode, compiler=COMPILE_GCC, stack=0xf000000,ssize=3):
        super(myEmu_stage_alloc, self).__init__(arch, mode, compiler, stack,ssize)

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
                # print(OSMetaClass_param)
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



def my_OSMetaClass(uc, out, args):
    global is_OSMetaClass_called

    is_OSMetaClass_called = True
    for i in args:
        OSMetaClass_param.append(i)

    return MAGIC_RET


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


def emulate_init(func_addr, function_end_addr, OSMetaClass_addr, addresses):
    a = myEmu_stage_init(UC_ARCH_ARM64, UC_MODE_ARM)
    a._createUc()

    a.alt(OSMetaClass_addr, my_OSMetaClass, 4, False)
    a.setTrace(TRACE_DATA_WRITE)
    a.setTrace(TRACE_CODE)
    for addr in addresses:
        a.alt(addr, my_stub, 0, False)
        
    a._emulate(func_addr, function_end_addr, [],1000000)

    return a
    # print("----- Start emu -----")
    # a.showTrace()
    

def emulate_alloc(func_addr, function_end_addr, new_addr, addresses):
    a = myEmu_stage_alloc(UC_ARCH_ARM64, UC_MODE_ARM)
    a.alt(new_addr, my_new, 2, False)
    a.setTrace(TRACE_DATA_WRITE)
    a.setTrace(TRACE_CODE)
    for addr in addresses:
        a.alt(addr, my_stub_new, 0, False)
        
    a._emulate(func_addr, function_end_addr, [],1000000)

    return a
    # print("----- Start emu -----")
    # a.showTrace()


def get_address_of_new(addr):
    start_addr = addr
    end_addr = GetFunctionAttr(addr, FUNCATTR_END)
    curr_addr = start_addr
    while curr_addr < end_addr-4:
        if GetMnem(curr_addr) == 'BL':
            op = GetOpnd(curr_addr, 0)
            if '__ZN8OSObjectnwEm' in op:
                return(LocByName(op))
        curr_addr += 4
    return None


def get_OSMetaClass_address(addr):
    start_addr = addr
    end_addr = GetFunctionAttr(addr, FUNCATTR_END)
    # print("Start addr -> " + hex(start_addr))
    # print("End addr   -> " + hex(end_addr))
    curr_addr = start_addr
    while curr_addr < end_addr-4:
        if GetMnem(curr_addr) == 'BL':
            op = GetOpnd(curr_addr, 0)
            # name = Demangle(op,GetLongPrm(INF_LONG_DN))
            # print(GetOperandValue(curr_addr,0))
            # if name and 'OSMetaClass' in name:
            if '__ZN11OSMetaClassC2EPKcPKS_j' in op:
                return(LocByName(op))
                break
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
    end_addr = GetFunctionAttr(addr, FUNCATTR_END)

    # Substract because of GetFunctionAttr return
    # address of next DWORD after end
    end_addr -= 4

    hooks = []

    while cur_addr <= end_addr:
        mnem = GetMnem(cur_addr)
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
            end_addr = GetFunctionAttr(cur_addr, FUNCATTR_END)
            continue

        cur_addr += 4

    return start_addr,end_addr,hooks


def parse_init_function(addr):
    global static_calls_of_osmetaclass
    global count_OSMetaClass_parsing

    static_calls_of_osmetaclass = 0
    hooks = []
    start_addr = addr
    cur_addr = start_addr

    end_addr = GetFunctionAttr(addr, FUNCATTR_END)
    end_addr -= 4
    
    while cur_addr <= end_addr:
        if GetMnem(cur_addr) == 'BL':# or GetMnem(cur_addr) == 'B':
            op = GetOpnd(cur_addr, 0)
            # name = Demangle(op, GetLongPrm(INF_LONG_DN))
            # print(name)
            # if name and 'OSMetaClass' in name:
            if '__ZN11OSMetaClassC2EPKcPKS_j' in op:
                count_OSMetaClass_parsing += 1
                static_calls_of_osmetaclass+=1

            else:
                hooks.append(LocByName(op))

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
    func = Qword(vtable_addr_local)
    vtable_functions = []
    used_function_names = []

    while func != 0 and (func&0xfffffff000000000)==0xfffffff000000000 and '__text' in SegName(func):
        # print("  Address = " + hex(func))

        # func_addr = GetFunctionAttr(func, FUNCATTR_START)
        # MakeCode(func)

        # if add_func(func) != 0:
        #     return False, []
        if idc.is_code(func) == False:
            MakeUnknown(Qword(vtable_addr_local), 1, idaapi.DOUNK_SIMPLE)
            # idaapi.autoWait()
            # if fptr != Qword(class_vtable + i * 8):
            #     print("BBBBBBBBBBBBBBBBBBBBBBB")
            # fptr = Qword(class_vtable + i * 8)
            MakeCode(Qword(vtable_addr_local))
            idaapi.autoWait()
        # MakeCode(func)
        # idaapi.autoWait()
        MakeFunction(Qword(vtable_addr_local))
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
                MakeCode(Qword(vtable_addr_local))
                idaapi.autoWait()
                MakeFunction(Qword(vtable_addr_local))
                idaapi.autoWait()
                MakeCode(mainfunc)
                if MakeFunction(mainfunc):
                    idaapi.autoWait()
                else:
                    print("  NOT RECONSTRUCT => 0x%016x" % (mainfunc))
            else:
                if MakeFunction(Qword(vtable_addr_local)):
                    idaapi.autoWait()
                else:
                    print("  NOT RECONSTRUCT => 0x%016x" % (Qword(vtable_addr_local)))

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
        func = Qword(vtable_addr_local)

    return True, vtable_functions


# Reconstruct parameters for call's to OSMetaClass::OSMetaClass
for seg in Segments():
    if '__mod_init_func' in get_segm_name(seg):
        name = get_segm_name(seg)
        driver_name = name.split(':')[0]

        start_addr = SegStart(seg)
        end_addr = SegEnd(seg)
        
        count_init_function = (end_addr - start_addr) / 8
        count_osmetaclass_function = 0

        print("Driver -> " + driver_name)
        print("    Count Init funcs -> %d" % (count_init_function))
        while start_addr < end_addr:
            # function_ptr = start_addr
            function_addr = Qword(start_addr)
            # function_end_addr = idc.get_func_attr(function_addr, FUNCATTR_END) # GetFunctionAttr(function_addr, FUNCATTR_END)

            # WTF: GetFunctionAttr(function_addr, FUNCATTR_END) RETURN addr of next function
            # if function_end_addr != idc.BADADDR:
            #     function_end_addr -= 4

            OSMetaClass_addr = get_OSMetaClass_address(function_addr)
            function_addr, function_end_addr, addresses = parse_init_function(function_addr)
            # print(addresses)
            # print(hex(OSMetaClass_addr))
            dynamic_calls_of_osmetaclass = 0
            a = emulate_init(function_addr, function_end_addr, OSMetaClass_addr, addresses)


            print("        Func -> 0x%016X" % (function_addr))
            print("        Found calls osmetaclass by emulate -> %d" % (dynamic_calls_of_osmetaclass))
            if dynamic_calls_of_osmetaclass!=static_calls_of_osmetaclass:
                print("        Found calls osmetaclass by static -> %d !" % (static_calls_of_osmetaclass))
            else:
                print("        Found calls osmetaclass by static -> %d" % (static_calls_of_osmetaclass))
            # IF FOUND OSMetaClass by parsing not eq FOUND OSMetaClass by emulating then
            # ADD DRIVER TO bad_driver LIST
            if dynamic_calls_of_osmetaclass!=static_calls_of_osmetaclass:
                bad_driver.append({'driver_name':driver_name, 'function':function_addr})
                a.showTrace()
                # done = True
                # break
            
            start_addr += 8 
        # if done:
        #     break


count_OSMetaClass_emul = 0
for i in init_calls.keys():
    count_OSMetaClass_emul += len(init_calls[i])
    
# print(init_calls["IOAcceleratorFamily"])
print("Found OSMetaClass by parsing   => " + str(count_OSMetaClass_parsing))
print("Found OSMetaClass by emulating => " + str(count_OSMetaClass_emul))
# print(bad_driver)

# Write to file class parents
fd = open('classes_iphone.txt', 'w')
# Rename parameters
for drv in init_calls.keys():
    print("")
    print(drv)
    for call in init_calls[drv]:
        class_ptr = call[0]
        class_name = GetString(call[1])
        class_name_meta = class_name + '::gMetaClass'

        i = 0
        MakeNameEx(class_ptr, class_name_meta, 0)
        
        class_parent = NameEx(BADADDR, call[2])
        class_parent_name = Demangle(class_parent, GetLongPrm(INF_LONG_DN))
        if class_parent_name:
            class_parent = class_parent_name

        fd.write('class ' + class_name + ': public ' + class_parent.replace('__gMetaClass','') + ' \n')
        class_size = call[3]
        
        class_vtable = call[4]
        for i in range(13):
            OpOff(class_vtable + i * 8, 0, 0)
            if i==12:
                fptr = Qword(class_vtable + i * 8)
                if fptr != 0:
                    if idc.is_code(fptr) == False:
                        MakeUnknown(fptr, 1, idaapi.DOUNK_SIMPLE)
                        # idaapi.autoWait()
                        if fptr != Qword(class_vtable + i * 8):
                            print("BBBBBBBBBBBBBBBBBBBBBBB")
                        # fptr = Qword(class_vtable + i * 8)
                        MakeCode(fptr)
                        idaapi.autoWait()

                    if idc.get_func_attr(fptr, FUNCATTR_START) == idc.BADADDR:
                        MakeFunction(fptr)
                        idaapi.autoWait()

        class_vtable_name = 'vtbl_' + class_name_meta
        
        MakeNameEx(class_vtable, class_vtable_name, 0)
        
        print("    (%s, %s, %s, %x) = &%s" % (NameEx(BADADDR, class_ptr),class_name,class_parent,class_size,class_vtable_name))

fd.close()

# Find alloc functions and emulate
for drv in init_calls.keys():
    for call in init_calls[drv]:
        # OpOff(class_gmeta_vtable_ptr + 12*8,0,0)
        class_name_caller = GetString(call[1])
        class_gmeta_vtable_ptr = call[4]
        class_gmeta_alloc_func = Qword(class_gmeta_vtable_ptr + 12*8)
        print("EMUL ALLOC -> " + class_name_caller + " " + hex(class_gmeta_vtable_ptr) + ' ' + hex(class_gmeta_alloc_func))

        if class_gmeta_alloc_func != 0:
            function_addr = class_gmeta_alloc_func
            # function_end_addr = GetFunctionAttr(function_addr, FUNCATTR_END)

            # WTF: GetFunctionAttr(function_addr, FUNCATTR_END) RETURN addr of next function
            # if function_end_addr != BADADDR:
            #     function_end_addr -= 4

            new_addr = get_address_of_new(function_addr)
            if new_addr == None:
                continue

            function_addr, function_end_addr, addresses = parse_alloc_function(function_addr)
            # print(addresses)
            # print(hex(new_addr))
            # print(hex(function_addr))
            # print(hex(function_end_addr))
            MakeNameEx(function_addr, class_name_caller + '::alloc', 0)
            a = emulate_alloc(function_addr, function_end_addr, new_addr, addresses)
            if is_new_called == True:
                bad_allocs.append({'function': function_addr, 'class_name': class_name_caller})
                print("EEEEEEEEERRRRRRRRRRRRRRRRRRROOOOOOOOOOOOOORRRRRRRRRRRRRRRRRRRRRRRRRRRRR")
                print("  * Start: 0x%016X" % function_addr)
                print("  * End:   0x%016X" % function_end_addr)
                print("  * Hooks:")
                print(addresses)
                a.showTrace()
                is_new_called = False

bad_creation = []

# a = fuck

for cls in alloc_calls.keys():
    # print("")
    # print(cls)

    # for call in alloc_calls[cls]:
    #     del_struc(get_struc_id('VTABLE_'+cls))
    #     del_struc(get_struc_id('CLASS_'+cls+'_%X'%call[0]))


    for call in alloc_calls[cls]:
        size = call[0]
        ppp = call[1]
        vtable = call[2]
        print(cls + ': ('+hex(size)+', ' + hex(ppp) + ') = ' + hex(vtable))
        MakeNameEx(vtable, 'vtbl_' + cls, 0)

        # Create struct CLASS_ClassName_HEXSIZE
        struct_was_created = create_class_struct(cls, size)

        # Reconstruct functions list for creating VTABLE_ClassName
        vtable_was_reconstruct, vtable_functions = reconstruct_vtable(vtable, cls)

        # Create struct VTABLE_ClassName
        vtable_was_created = False
        if vtable_was_reconstruct:
            vtable_was_created = create_vtable_struct(cls, vtable_functions)

        if vtable_was_created and struct_was_created:
            msid = get_struc_id('VTABLE_'+cls)
            ssid = get_struc_id('CLASS_'+cls+'_%X' % size)
            # et_member_type(ssid, 0, FF_0STRO, msid, 1)
            SetType(get_member_id(ssid, 0), 'struct VTABLE_' + cls + ' *')
            SetType(vtable, 'struct VTABLE_' + cls)

        else:
            bad_creation.append(cls)



print("[!] STAGE EMULATION INIT ERRORS:")
pprint.pprint(bad_driver)
print("[!] STAGE EMULATION ALLOC ERRORS:")
pprint.pprint(bad_allocs)
print("[i] STAGE CREATION classes and/or vtables ERROR:")
pprint.pprint(bad_creation)