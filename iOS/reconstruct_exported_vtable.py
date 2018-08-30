import idc
import idautils
import idaapi
import pprint
import sys
from idaemu import *

MAGIC_RET = 0x4141414141

is_OSMetaClass_called = False
OSMetaClass_param = []
driver_name = ''
bad_driver = []
done = False
z = 0
count_OSMetaClass_parsing = 0
y = 0

init_calls = {}


class myEmu(Emu):
    def __init__(self, arch, mode, compiler=COMPILE_GCC, stack=0xf000000,ssize=3):
        super(myEmu, self).__init__(arch, mode, compiler, stack,ssize)

    def _hook_mem_invalid(self, uc, access, address, size, value, user_data):
        addr = self._alignAddr(address)
        uc.mem_map(addr, PAGE_ALIGN)
        data = self._getOriginData(addr, PAGE_ALIGN)
        uc.mem_write(addr, data)
        return True

    def _hook_mem_access(self, uc, access, address, size, value, user_data):
        global is_OSMetaClass_called
        global OSMetaClass_param
        global y
        
        if access == UC_MEM_WRITE and is_OSMetaClass_called == True: #self.traceOption & TRACE_DATA_WRITE:
            is_OSMetaClass_called = False
            X8 = uc.reg_read(UC_ARM64_REG_X8)
            X0 = uc.reg_read(UC_ARM64_REG_X0)
            # print(hex(X8))
            # print(hex(X0))
            if MAGIC_RET == X0:
                OSMetaClass_param.append(X8)
                if driver_name not in init_calls.keys():
                    init_calls[driver_name] = []
                init_calls[driver_name].append(OSMetaClass_param)
                y+=1
                # print(OSMetaClass_param)
                OSMetaClass_param = []
            else:
                print("ERRRRRRRRRRRRRRRRRRRRORRRRRRRRRRRR")
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


def my_stub(uc,out,args):
    return 0


def emulate_init(func_addr, function_end_addr, OSMetaClass_addr, addresses):
    a = myEmu(UC_ARCH_ARM64, UC_MODE_ARM)
    a.alt(OSMetaClass_addr, my_OSMetaClass, 4, False)
    a.setTrace(TRACE_DATA_WRITE)
    # a.setTrace(TRACE_CODE)
    for addr in addresses:
        a.alt(addr, my_stub, 0, False)
        
    a._emulate(func_addr, function_end_addr, [],1000000)

    # print("----- Start emu -----")
    # a.showTrace()


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

def get_Function_addresses(addr):
    global z
    global count_OSMetaClass_parsing

    z = 0
    addresses = []
    start_addr = addr
    end_addr = GetFunctionAttr(addr, FUNCATTR_END)
    curr_addr = start_addr
    while curr_addr < end_addr-4:
        if GetMnem(curr_addr) == 'BL':
            op = GetOpnd(curr_addr, 0)
            # name = Demangle(op, GetLongPrm(INF_LONG_DN))
            # print(name)
            # if name and 'OSMetaClass' in name:
            if '__ZN11OSMetaClassC2EPKcPKS_j' in op:
                count_OSMetaClass_parsing += 1
                z+=1
            else:
                addresses.append(LocByName(op))
        curr_addr += 4
    return addresses
    

for ea in Segments():
    if '__mod_init_func' in get_segm_name(ea):
        name = get_segm_name(ea)
        driver_name = name.split(':')[0]

        start_addr = SegStart(ea)
        end_addr = SegEnd(ea)
        
        count_init_function = (end_addr - start_addr) / 8
        count_osmetaclass_function = 0

        print("Driver -> " + driver_name)
        print("    Count Init funcs -> " + str(count_init_function))
        while start_addr < end_addr:
            function_ptr = start_addr
            function_addr = Qword(start_addr)
            function_end_addr = GetFunctionAttr(function_addr, FUNCATTR_END)

            # WTF: GetFunctionAttr(function_addr, FUNCATTR_END) RETURN addr of next function
            if function_end_addr != BADADDR:
                function_end_addr -= 4

            OSMetaClass_addr = get_OSMetaClass_address(function_addr)
            addresses = get_Function_addresses(function_addr)
            # print(addresses)
            # print(hex(OSMetaClass_addr))
            y = 0
            emulate_init(function_addr, function_end_addr, OSMetaClass_addr, addresses)


            print("        Func -> %X" % (function_addr))
            print("        Emul calls osmetaclass  -> %d" % (y))
            if y!=z:
                print("        Found calls osmetaclass -> %d !" % (z))
            else:
                print("        Found calls osmetaclass -> %d" % (z))
            # IF FOUND OSMetaClass by parsing not eq FOUND OSMetaClass by emulating then
            # ADD DRIVER TO bad_driver LIST
            if y!=z:
                bad_driver.append({'driver_name':driver_name, 'function':function_addr})
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

fd = open('7plus_10.3.1.txt', 'w')

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
        class_vtable_name = 'VTABLE_' + class_name_meta
        
        MakeNameEx(class_vtable, class_vtable_name, 0)
        
        print("    (%s, %s, %s, %x) = &%s" % (NameEx(BADADDR, class_ptr),class_name,class_parent,class_size,class_vtable_name))

fd.close()

print(bad_driver)
