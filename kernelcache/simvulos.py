import idc
import ida_name
import ida_bytes
import ida_idaapi
import ida_struct
import ida_kernwin

def main():
    start = ida_kernwin.get_screen_ea()
    cur_qword = ida_bytes.get_qword(start)
    vtable = []
    while cur_qword != 0:
        start += 8
        name = ida_name.get_name(cur_qword)
        # print(hex(cur_qword) + " : " + name)
        vtable.append(name)
        cur_qword = ida_bytes.get_qword(start)

    vtable_name = ida_kernwin.ask_str('', -1, 'Vtable name')
    if vtable_name == '' or vtable_name == None:
        return

    struc_tid = ida_struct.get_struc_id(vtable_name)
    struc = ida_struct.get_struc(struc_tid)

    if struc == None:
        print("[-] vtable struct wasn't found")
        return

    for func in vtable:
        ida_struct.add_struc_member(
            struc,
            func,
            ida_idaapi.BADADDR,
            idc.FF_QWORD,
            None,
            8
        )

class SimvulosPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_PROC
    comment = "Simvulos"
    help = "Scan vtable and fill struct with names"
    wanted_name = "Simvulos"
    wanted_hotkey = "Shift+S"


    def init(self):
        return ida_idaapi.PLUGIN_OK

    def run(self, arg):
        main()

    def term(self):
        return

def PLUGIN_ENTRY():
    return SimvulosPlugin()
