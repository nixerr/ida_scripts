import idautils
import ida_funcs
import ida_search
import ida_idaapi
import ida_strlist
import ida_bytes
import ida_idc


base_ea = idaapi.get_imagebase()
end_ea = ida_segment.get_last_seg().start_ea
slot = 0

def mark(name):
    global slot
    name_addr = get_name_ea_simple(name)
    if name_addr == ida_idaapi.BADADDR:
        return

    ida_idc.mark_position(name_addr, -1, 0, 0, slot, name)
    slot += 1


def count_xref_to_func(ea):
    return len(list(idautils.XrefsTo(ea)))


def find_string_address(s):
    sc = ida_strlist.string_info_t()
    for i in range(0,ida_strlist.get_strlist_qty()):
        ida_strlist.get_strlist_item(sc,i)
        c = ida_bytes.get_strlit_contents(sc.ea,sc.length,sc.type)
        if c and c == s.encode():
            return sc.ea

    return ida_idaapi.BADADDR


def find_function_with_string(s):
    s_addr = find_string_address(s)
    if s_addr != ida_idaapi.BADADDR:
        for xref in idautils.XrefsTo(s_addr):
            func = idaapi.get_func(xref.frm)
            return func.start_ea

    return ida_idaapi.BADADDR


def define_function_by_string(n, s):
    f = find_function_with_string(s)
    if f != ida_idaapi.BADADDR:
        idc.set_name(f, n, idc.SN_CHECK)
        print("[+] {}: 0x{:016x}".format(n, f))
    else:
        print("[-] {} not found".format(n))


def find_panic():
    panic_trap_to_debugger_addr = get_name_ea_simple("panic_trap_to_debugger")
    xrefs = idautils.XrefsTo(panic_trap_to_debugger_addr)
    max_n = 0
    panic = 0
    for xref in xrefs:
        f = ida_funcs.get_func(xref.frm)
        if f == None:
            continue
        n = count_xref_to_func(f.start_ea)
        if n > max_n:
            max_n = n
            panic = f.start_ea

    set_name(panic, "_panic")
    print("[+] panic: 0x{0:x}".format(panic))


def find_os_log_internal():
    failed_to_init_addr = find_string_address("failed to initialize compression: %d!\n")
    xrefs = idautils.XrefsTo(failed_to_init_addr)
    max_step = 8
    insn = ida_ua.insn_t()
    for xref in xrefs:
        curr_addr = xref.frm
        while max_step:
            curr_addr += 4
            max_step -= 1
            if ida_ua.print_insn_mnem(curr_addr) == 'BL' and ida_ua.decode_insn(insn, curr_addr):
                if len(insn.ops) > 1:
                    os_log_internal_addr = insn.ops[0].addr
                    set_name(os_log_internal_addr, "__os_log_internal")
                    print("[+] __os_log_internal: 0x{:016x}".format(os_log_internal_addr))
                    return

    print("[-] not found: __os_log_internal")


def find_common_functions():
    define_function_by_string("vm_map_init", "vm_memory_malloc_no_cow_mask")
    define_function_by_string("load_static_trust_cache", "unexpected size for TrustCache property: %u != %zu @%s:%d")
    define_function_by_string("trust_cache_runtime_init", "image4 interface not available @%s:%d")
    define_function_by_string("mig_init", "multiple entries with the same msgh_id @%s:%d")
    define_function_by_string("kmem_init", "kmem_init(0x%llx,0x%llx): vm_map_enter(0x%llx,0x%llx) error 0x%x @%s:%d")
    define_function_by_string("__strncpy_chk", "__strncpy_chk object size check failed: dst %p, src %p, (%zu < %zu) @%s:%d")
    define_function_by_string("assert", "%s:%d Assertion failed: %s")
    define_function_by_string("__stack_chk_fail", "stack_protector.c")
    define_function_by_string("arm_init", "arm_init")
    define_function_by_string("kernel_bootstrap", "load_context - done")
    define_function_by_string("__ZN11OSMetaClassC2EPKcPKS_j", "OSMetaClass: preModLoad() wasn't called for class %s (runtime internal error).")


def find_mig_e():
    mig_init_addr = get_name_ea_simple("mig_init")
    # skip PACIBSP
    mig_init_addr += 4
    max_step = 8
    insn = ida_ua.insn_t()
    while max_step:
        max_step -= 1
        if ida_ua.print_insn_mnem(mig_init_addr) == 'ADRL' and ida_ua.decode_insn(insn, mig_init_addr):
            if len(insn.ops) > 2 and insn.ops[1].type == ida_ua.o_imm:
                mig_e_addr = insn.ops[1].value
                set_name(mig_e_addr, "mig_e", idc.SN_CHECK)
                print("[+] mig_e: 0x{:016x}".format(mig_e_addr))
                return
        mig_init_addr += 4


def find_PE_parse_boot_argn_internal():
    maxmem_addr = find_string_address("maxmem")
    if maxmem_addr != ida_idaapi.BADADDR:
        for xref in idautils.XrefsTo(maxmem_addr):
            cur_addr = xref.frm
            max_step = 5
            insn = ida_ua.insn_t()
            while max_step:
                max_step -= 1
                cur_addr += 4
                if ida_ua.decode_insn(insn, cur_addr):
                    if ida_idp.is_call_insn(insn) and insn.ops[0].type == ida_ua.o_near:
                        func = insn.ops[0].addr
                        idc.set_name(func, "PE_parse_boot_argn_internal", idc.SN_CHECK)
                        print("[+] PE_parse_boot_argn_internal: 0x{0:x}".format(func))
                        return

    print("[-] PE_parse_boot_argn_internal not found")
    return


def find_mac_policy_register():
    define_function_by_string("mac_policy_register", "policy's name is not set @%s:%d")


def find_ExceptionVectorsBase():
    MSR_VBAR = "? C0 18 D5"
    msr_vbar_addr = ida_search.find_binary(base_ea, end_ea, MSR_VBAR, 16, ida_search.SEARCH_DOWN)
    insn = ida_ua.insn_t()
    while msr_vbar_addr != ida_idaapi.BADADDR:
        reg_num = ida_bytes.get_dword(msr_vbar_addr) & 0xff

        num_steps = 5
        cur_addr = msr_vbar_addr - 4
        candidate = 0
        while num_steps != 0:
            if ida_ua.print_insn_mnem(cur_addr) == 'ADRL' and ida_ua.decode_insn(insn, cur_addr):
                if len(insn.ops) > 2 and insn.ops[1].type == ida_ua.o_imm:
                    candidate = insn.ops[1].value
                    break
            num_steps -= 1
            cur_addr -= 4

        if ida_bytes.get_dword(candidate) != 0x14000000:
            set_name(candidate, "ExceptionVectorsBase", idc.SN_CHECK)
            print("[i] ExceptionVectorsBase: 0x{:016x}".format(candidate))
            return
        msr_vbar_addr = ida_search.find_binary(msr_vbar_addr+2, end_ea, MSR_VBAR, 16, ida_search.SEARCH_DOWN)


def find_mig_subsystems():
    known_subsystems = {
        '716200': 'mach_eventlink_subsystem',
        '2405':   'catch_mach_exc_subsystem',
        '2401':   'catch_exc_subsystem',
        '8000':   'task_restartable_subsystem',
        '4900':   'memory_entry_subsystem',
        '5400':   'mach_voucher_subsystem',
        '3800':   'vm32_map_subsystem',
        '3600':   'thread_act_subsystem',
        '3400':   'task_subsystem',
        '2800':   'is_iokit_subsystem',
        '4000':   'processor_set_subsystem',
        '3000':   'processor_subsystem',
        '1000':   'clock_subsystem',
        '400':    'host_priv_subsystem',
        '200':    'mach_host_subsystem',
        '3200':   'mach_port_subsystem',
        '4800':   'mach_vm_subsystem'
    }
    mig_e_addr = get_name_ea_simple("mig_e")
    subsystems_addr = ida_bytes.get_qword(mig_e_addr)
    while subsystems_addr & 0xfffffff000000000 ==  0xfffffff000000000:
        num_start = ida_bytes.get_dword(subsystems_addr+8)
        num_end = ida_bytes.get_dword(subsystems_addr+12)
        subsystems_name = ''
        if str(num_start) in known_subsystems.keys():
            subsystems_name = known_subsystems[str(num_start)]
        else:
            subsystems_name = 'mig_subsystem_' + str(num_start)
        idc.set_name(subsystems_addr, subsystems_name, idc.SN_CHECK)
        print("[+] {}: 0x{:016x}".format(subsystems_name, subsystems_addr))

        mig_e_addr += 8
        subsystems_addr = ida_bytes.get_qword(mig_e_addr)


if __name__ == '__main__':
    find_common_functions()
    find_panic()
    find_os_log_internal()
    find_mac_policy_register()
    find_PE_parse_boot_argn_internal()
    find_mig_e()
    find_mig_subsystems()
    find_ExceptionVectorsBase()

    need_to_mark = [
        "ExceptionVectorsBase",
        "vm_map_init",
        "mig_e",
        "arm_init"
    ]
    for n in need_to_mark:
        mark(n)
