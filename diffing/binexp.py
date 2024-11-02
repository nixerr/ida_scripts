
import idautils
import idaapi
import idc

idc.auto_wait()
binexport_name = idc.ARGV[1]
idaapi.ida_expr.eval_idc_expr(None, ida_idaapi.BADADDR, 'BinExportBinary("{}");'.format(binexport_name))

idc.qexit(0)
