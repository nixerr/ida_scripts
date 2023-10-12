import ida_ua
import ida_idp
import ida_bytes
import ida_segregs
import ida_idaapi

MNEM_WIDTH = 16

class GXFInstructions:
    (GENTER, GEXIT, GXF_UNKN1, GXF_UNKN2) = range(ida_idp.CUSTOM_INSN_ITYPE, ida_idp.CUSTOM_INSN_ITYPE+4)
    GENTER_MASK = 0xFFFFFFE0
    GENTER_CODE = 0x00201420
    GEXIT_CODE  = 0x00201400
    UNKN_CODE1  = 0x00201462
    UNKN_CODE2  = 0xE7FFDEFF
    UNKN_CODE3  = 0x00201220
    UNKN_CODE3  = 0x00201221

    lst = {
        GENTER: "GENTER",
        GEXIT:  "GEXIT",
        GXF_UNKN1: "GXF_UNKN1",
        GXF_UNKN2: "GXF_UNKN2"
    }

    @staticmethod
    def IsGENTER(code):
        return code & GXFInstructions.GENTER_MASK == GXFInstructions.GENTER_CODE

    @staticmethod
    def IsGEXIT(code):
        return code == GXFInstructions.GEXIT_CODE

    @staticmethod
    def IsGXF_UNKN1(code):
        return code == GXFInstructions.UNKN_CODE1

    @staticmethod
    def IsGXF_UNKN2(code):
        return code == GXFInstructions.UNKN_CODE2

class GXFHook(ida_idp.IDP_Hooks):

    def __init__(self):
        ida_idp.IDP_Hooks.__init__(self)
        self.reported = []

    def ev_ana_insn(self, insn):
        code = ida_bytes.get_wide_dword(insn.ea)

        if GXFInstructions.IsGENTER(code):
            insn.itype = GXFInstructions.GENTER
            insn.size = 4

            insn.Op1.type = ida_ua.o_imm
            insn.Op1.value = code & ~GXFInstructions.GENTER_MASK
            return True

        elif GXFInstructions.IsGEXIT(code):
            insn.itype = GXFInstructions.GEXIT
            insn.size = 4
            return True

        elif GXFInstructions.IsGXF_UNKN1(code):
            insn.itype = GXFInstructions.GXF_UNKN1
            insn.size = 4
            return True

        elif GXFInstructions.IsGXF_UNKN2(code):
            insn.itype = GXFInstructions.GXF_UNKN2
            insn.size = 4
            return True

        return False

    def ev_emu_insn(self, insn):
        if insn.itype == GXFInstructions.GENTER:
            return 0 # continue code flow
        elif insn.itype == GXFInstructions.GEXIT:
            return 1 # stop code flow
        elif insn.itype in [GXFInstructions.GXF_UNKN1, GXFInstructions.GXF_UNKN2]:
            return 0
        # use default processing for all other functions
        return 0

    def ev_out_mnem(self, outctx):
        insntype = outctx.insn.itype

        if (insntype >= ida_idp.CUSTOM_INSN_ITYPE) and (insntype in GXFInstructions.lst):
            mnem = GXFInstructions.lst[insntype]
            outctx.out_custom_mnem(mnem, MNEM_WIDTH)
            return True
        # if outctx.insn.itype == GXFInstructions.GENTER:
        #     outctx.out_custom_mnem("GENTER", MNEM_WIDTH)
        #     return True
        # elif outctx.insn.itype == GXFInstructions.GEXIT:
        #     outctx.out_custom_mnem("GEXIT", MNEM_WIDTH)
        #     return True
        return False

    # def ev_out_operand(self, outctx, op):
    #     pass

class GXFExtensionPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_PROC | ida_idaapi.PLUGIN_HIDE
    comment = ""
    wanted_hotkey = ""
    help = "Adds support for additional Apple GXF instructions"
    wanted_name = "GXFExtensionPlugin"

    def __init__(self):
        self.prochook = None

    def init(self):
        if ida_idp.ph_get_id() != ida_idp.PLFM_ARM:
            return ida_idaapi.PLUGIN_SKIP

        self.prochook = GXFHook()
        self.prochook.hook()
        print ("%s initialized." % GXFExtensionPlugin.wanted_name)
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        if self.prochook:
            self.prochook.unhook()

def PLUGIN_ENTRY():
    return GXFExtensionPlugin()
