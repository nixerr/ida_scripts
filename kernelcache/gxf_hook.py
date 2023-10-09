import ida_idp
import ida_bytes
import ida_segregs

ITYPE_GENTER = ida_idp.CUSTOM_INSN_ITYPE + 10
ITYPE_GEXIT  = ITYPE_GENTER + 1
MNEM_WIDTH = 16

GENTER_CODE = 0x00201420
GEXIT_CODE  = 0x00201400

class MyHooks(ida_idp.IDP_Hooks):

    def __init__(self):
        ida_idp.IDP_Hooks.__init__(self)
        self.reported = []

    def ev_ana_insn(self, insn):
        if ida_bytes.get_wide_dword(insn.ea) == GENTER_CODE:
            insn.itype = ITYPE_GENTER
            insn.size = 4
        elif ida_bytes.get_wide_dword(insn.ea) == GEXIT_CODE:
            insn.itype = ITYPE_GEXIT
            insn.size = 4
        return insn.size

    def ev_emu_insn(self, insn):
        if insn.itype == ITYPE_GENTER:
            return 0 # continue code flow
        elif insn.itype == ITYPE_GEXIT:
            return 1 # stop code flow
        # use default processing for all other functions
        return 0

    def ev_out_mnem(self, outctx):
        if outctx.insn.itype == ITYPE_GENTER:
            outctx.out_custom_mnem("GENTER", MNEM_WIDTH)
            return 1
        elif outctx.insn.itype == ITYPE_GEXIT:
            outctx.out_custom_mnem("GEXIT", MNEM_WIDTH)
            return 1
        return 0

if ida_idp.ph.id == ida_idp.PLFM_ARM:
    bahooks = MyHooks()
    bahooks.hook()
    print("GXF processor extension installed")
else:
    warning("This script only supports ARM files")
