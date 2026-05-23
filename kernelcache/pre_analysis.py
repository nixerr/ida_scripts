import ida_segment
import ida_funcs
import ida_ua
import ida_name
import idaapi
import ida_bytes
import idautils
import idc

def make_kernel_const_segments_rw():
    for segment in idautils.Segments():
        if 'com.apple.kernel:__const' in idc.get_segm_name(segment):
            seg = ida_segment.getseg(segment)
            seg.perm = ida_segment.SEGPERM_READ | ida_segment.SEGPERM_WRITE
            seg.update()
            print(f'[i] make \'com.apple.kernel:__const\' (0x{seg.start_ea:x}) writtable')

def find_panic_trap_to_debugger():
    base_ea     = idaapi.get_imagebase()
    end_ea      = ida_segment.get_last_seg().start_ea
    HINT_45h    = "BF 28 03 D5"
    PACIBSP     = "7F 23 03 D5"

    hint        = ida_bytes.find_bytes(HINT_45h, base_ea)
    func_start  = ida_bytes.find_bytes(PACIBSP, base_ea, None, hint, None, ida_bytes.BIN_SEARCH_BACKWARD, 16)
    func_end    = ida_bytes.find_bytes(PACIBSP, hint, None, end_ea, None, ida_bytes.BIN_SEARCH_FORWARD, 16)

    cur_addr = func_start
    while cur_addr != func_end:
        ida_ua.create_insn(cur_addr)
        cur_addr += 4

    func_str = ida_funcs.func_t(func_start, func_end, ida_funcs.FUNC_NORET)

    if (ida_funcs.add_func_ex(func_str)):
        ida_name.set_name(func_start, "panic_trap_to_debugger")
    print(f"[i] panic_trap_to_debugger: 0x{func_start:x}")

def run():
    make_kernel_const_segments_rw()
    find_panic_trap_to_debugger()

if __name__ == '__main__':
    run()
