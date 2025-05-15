import ida_segment
import ida_search
import ida_funcs
import ida_ua
import ida_name
import idaapi
# import idalog
# import logging

def find_panic_trap_to_debugger():
    base_ea     = idaapi.get_imagebase()
    end_ea      = ida_segment.get_last_seg().start_ea
    HINT_45h    = "BF 28 03 D5"
    PACIBSP     = "7F 23 03 D5"

    hint        = ida_search.find_binary(base_ea, end_ea, HINT_45h, 16, 0)
    func_start  = ida_search.find_binary(base_ea, hint, PACIBSP, 16, ida_search.SEARCH_UP)
    func_end    = ida_search.find_binary(hint, end_ea, PACIBSP, 16, ida_search.SEARCH_DOWN)

    cur_addr = func_start
    while cur_addr != func_end:
        ida_ua.create_insn(cur_addr)
        cur_addr += 4

    func_str = ida_funcs.func_t(func_start, func_end, ida_funcs.FUNC_NORET)

    if (ida_funcs.add_func_ex(func_str)):
        ida_name.set_name(func_start, "panic_trap_to_debugger")
    print("[i] panic_trap_to_debugger: 0x{0:x}".format(func_start))

def run():
    find_panic_trap_to_debugger()

if __name__ == '__main__':
    run()
