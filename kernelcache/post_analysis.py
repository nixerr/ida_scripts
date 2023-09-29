import idautils
import ida_funcs
import ida_search
import ida_idaapi

base_ea = idaapi.get_imagebase()
end_ea = ida_segment.get_last_seg().start_ea

def count_xref_to_func(ea):
    return len(list(idautils.XrefsTo(ea)))

def find_panic():
    panic_trap_to_debugger_addr = get_name_ea_simple("panic_trap_to_debugger")
    xrefs = idautils.XrefsTo(panic_trap_to_debugger_addr)
    max_n = 0
    panic = 0
    for xref in xrefs:
        f = ida_funcs.get_func(xref.frm)
        n = count_xref_to_func(f.start_ea)
        if n > max_n:
            max_n = n
            panic = f.start_ea
    
    set_name(panic, "_panic")
    print("[+] panic: 0x{0:x}".format(panic))


def find_stack_chk_fail():
    stack_protector_addr = ida_search.find_text(base_ea, 1, 1, "stack_protector.c", ida_search.SEARCH_DOWN)
    if stack_protector_addr != ida_idaapi.BADADDR:
        for xref in idautils.XrefsTo(stack_protector_addr):
            func = idaapi.get_func(xref.frm)
            idc.set_name(func.start_ea, "__stack_chk_fail", idc.SN_CHECK)
            print("[+] __stack_chk_fail: 0x{0:x}".format(func.start_ea))
            return

    print("[-] __stack_chk_fail not found")
    return


def find_assert():
    assert_addr = ida_search.find_text(base_ea, 1, 1, "%s:%d Assertion failed: %s", ida_search.SEARCH_DOWN)
    if assert_addr != ida_idaapi.BADADDR:
        for xref in idautils.XrefsTo(assert_addr):
            func = idaapi.get_func(xref.frm)
            idc.set_name(func.start_ea, "assert", idc.SN_CHECK)
            print("[+] assert: 0x{0:x}".format(func.start_ea))
            return
            
    print("[-] assert not found")
    return


def find_mig_init():
    mig_init_panic = ida_search.find_text(base_ea, 1, 1, "multiple entries with the same msgh_id @%s:%d", ida_search.SEARCH_DOWN)
    if mig_init_panic != ida_idaapi.BADADDR:
        for xref in idautils.XrefsTo(mig_init_panic):
            func = idaapi.get_func(xref.frm)
            idc.set_name(func.start_ea, "mig_init", idc.SN_CHECK)
            print("[+] mig_init: 0x{0:x}".format(func.start_ea))
            return

    print("[-] mig_init not found")
    return


def find_ExceptionVectorsBase():
    MSR_VBAR = "? C0 18 D5"

    msr_vbar_addr = ida_search.find_binary(base_ea, end_ea, MSR_VBAR, 16, 0)

# mach_eventlink_subsystem      716200  716200
# catch_mach_exc_subsystem      2405    2410
# catch_exc_subsystem           2401    2404
# task_restartable_subsystem    8000    8002
# memory_entry_subsystem        4900    4903
# mach_voucher_subsystem        5400    5405
# vm32_map_subsystem            3800    3832
# thread_act_subsystem          3600    3631
# task_subsystem                3400    3465
# is_iokit_subsystem            2800    2891
# processor_set_subsystem       4000    4011
# processor_subsystem           3000    3006
# clock_subsystem               1000    1003
# host_priv_subsystem           400     426
# mach_host_subsystem           200     235
# mach_port_subsystem           3200    3243
# mach_vm_subsystem             4800    4826

if __name__ == '__main__':
    # find_panic()
    # find_stack_chk_fail()
    # find_assert()
    # find_mig_init()
    find_ExceptionVectorsBase()