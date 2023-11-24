import idautils
import ida_kernwin
import ida_name

cstring_end    = None
cstring_start  = None
os_log_end     = None
os_log_start   = None
text_start     = None
text_end       = None
driver_name    = None

TEMPLATE = """
import idautils
import ida_funcs
import ida_search
import ida_idaapi
import ida_strlist
import ida_bytes
import ida_idc

driver_name       = "__DRIVER_NAME__"
strs              = None
strings           = None
strings_list      = None
strings_counts    = None
strings_uniqness  = None
is_strings_inited = False

cstring_end       = None
cstring_start     = None
os_log_end        = None
os_log_start      = None


def init():
  global cstring_end
  global cstring_start
  global os_log_end
  global os_log_start

  if driver_name == None:
    print("[-] driver_name: None")
    return False

  segs                = idautils.Segments()
  is_next_cstring_end = False
  is_next_os_log_end  = False
  for seg_ea in segs:
    seg = ida_segment.getseg(seg_ea)
    seg_name = ida_segment.get_segm_name(seg)

    if is_next_cstring_end == True and cstring_end == None:
      cstring_end = seg_ea
      is_next_cstring_end = False

    if is_next_os_log_end == True and os_log_end == None:
      os_log_end = seg_ea
      is_next_os_log_end = False

    if None not in [cstring_start, cstring_end,
                os_log_start, os_log_end]:
      break

    if driver_name in seg_name and '__cstring' in seg_name:
      cstring_start = seg_ea
      is_next_cstring_end = True
      continue

    if driver_name in seg_name and '__os_log' in seg_name:
      os_log_start = seg_ea
      is_next_os_log_end = True
      continue


  if cstring_start == None or os_log_start == None:
    print("[-] Not found needed segments")
    return False

  print("[+] Found needed segments:")
  print("  * cstring: 0x{:016x} - 0x{:016x}".format(cstring_start, cstring_end))
  print("  * os_log: 0x{:016x} - 0x{:016x}".format(os_log_start, os_log_end))

  return True


def is_os_log(ea):
  return os_log_start <= ea < os_log_end


def is_cstring(ea):
  return cstring_start <= ea < cstring_end


def count_xref_to(ea):
  return len(list(idautils.XrefsTo(ea)))


def xref_is_func(ea):
  for xref in idautils.XrefsTo(ea):
    func = idaapi.get_func(xref.frm)
    if func == None:
      return False
    return True


def are_xrefs_only_from_one_func(ea):
  func_addr = None
  for xref in idautils.XrefsTo(ea):
    func = idaapi.get_func(xref.frm)
    if func == None:
      return False
    if func_addr == None:
      func_addr = func.start_ea
    elif func_addr == func.start_ea:
      continue
    else:
      return False
  return True


def get_func_addr_from_xref(ea):
  for xref in idautils.XrefsTo(ea):
    func = idaapi.get_func(xref.frm)
    return func.start_ea


def define_function_by_addr(n, ea):
  idc.set_name(ea, n, idc.SN_CHECK)
  print("[+] {}: 0x{:016x}".format(n, f))


def is_stringable(ea):
  xrefs = count_xref_to(ea)
  if xrefs == 0:
    return False
  elif xrefs == 1:
    return xref_is_func(ea)
  elif xrefs > 1:
    return are_xrefs_only_from_one_func(ea)

def init_strings():
  global strs
  global strings
  global strings_list
  global strings_counts
  global strings_uniqness
  global is_strings_inited

  if is_strings_inited == True:
    return
  strs = idautils.Strings()
  strings = [s for s in strs if is_os_log(s.ea) or is_cstring(s.ea)]
  strings_list = [repr(str(s)) for s in strings]
  strings_counts = {repr(str(i)):strings_list.count(repr(str(i))) for i in strings}
  strings_uniqness = [i for i in strings_counts.keys() if strings_counts[i] == 1]
  is_strings_inited = True


def main():
  if init() == False:
    return

  init_strings()

  def is_uniq(s):
    if repr(str(s)) in strings_uniqness: return True
    else: return False

  strings = [s for s in strs if (is_cstring(s.ea) or is_os_log(s.ea)) and is_uniq(s)]

  def find_string_address(inp_s):
    for s in strings:
      if repr(str(s)) == repr(inp_s):
        return s.ea
    return ida_idaapi.BADADDR


  def find_function_with_string(s):
    s_addr = find_string_address(s)
    if is_stringable(s_addr):
      return get_func_addr_from_xref(s_addr)
    return ida_idaapi.BADADDR

  def find_candidate_func(list_of_strings):
    func_addr = None
    for s in list_of_strings:
      if func_addr == None or func_addr == ida_idaapi.BADADDR:
        func_addr = find_function_with_string(s)
        continue

      new_func_addr = find_function_with_string(s)
      if new_func_addr != ida_idaapi.BADADDR and new_func_addr != func_addr:
        return ida_idaapi.BADADDR
    return func_addr

  def func_has_non_default_name(func_addr):
    func_name = ida_name.get_name(func_addr)
    if func_name.startswith('sub_'):
      return False
    return True

  def rename_func(func_name, rename_type, list_of_strings):
    if rename_type == "s":
      func_addr = find_candidate_func(list_of_strings)
      if func_addr == ida_idaapi.BADADDR:
        return False
      if func_has_non_default_name(func_addr) == True:
        return False
      idc.set_name(func_addr, func_name, idc.SN_CHECK)
      print("[+] Found function '{:s}' at 0x{:016x}".format(func_name, func_addr))
      return True
    elif rename_type == "f":
      candidate = None
      for f_name in list_of_strings:
        func_addr = get_name_ea_simple(f_name)
        if (candidate == None or candidate == ida_idaapi.BADADDR) and func_addr != ida_idaapi.BADADDR and is_stringable(func_addr):
          candidate = get_func_addr_from_xref(func_addr)
          continue

        func_addr = get_name_ea_simple(f_name)
        if func_addr != ida_idaapi.BADADDR and is_stringable(func_addr) and get_func_addr_from_xref(func_addr) != candidate:
          return False
      if candidate == None or candidate == ida_idaapi.BADADDR:
        return False

      if func_has_non_default_name(candidate) == True:
        return False
      idc.set_name(candidate, func_name, idc.SN_CHECK)
      print("[+] Found function '{:s}' at 0x{:016x}".format(func_name, candidate))
      return True

  results = [True]
  while True in results:
    results = []
__RENAME_FUNCS_LIST__

main()
"""

def init():
  global cstring_end
  global cstring_start
  global os_log_end
  global os_log_start
  global text_start
  global text_end
  global driver_name

  driver_name = ida_kernwin.ask_str("", 0, "Driver name")
  if driver_name == None or driver_name == "":
    print("[-] driver_name: None")
    return False

  segs                = idautils.Segments()
  is_next_cstring_end = False
  is_next_text_end    = False
  is_next_os_log_end  = False
  for seg_ea in segs:
    seg = ida_segment.getseg(seg_ea)
    seg_name = ida_segment.get_segm_name(seg)

    if is_next_cstring_end == True and cstring_end == None:
      cstring_end = seg_ea
      is_next_cstring_end = False

    if is_next_text_end == True and text_end == None:
      text_end = seg_ea
      is_next_text_end = False

    if is_next_os_log_end == True and os_log_end == None:
      os_log_end = seg_ea
      is_next_os_log_end = False

    if None not in [text_start, text_end,
                cstring_start, cstring_end,
                os_log_start, os_log_end]:
      break

    if driver_name in seg_name and '__cstring' in seg_name and cstring_start == None:
      cstring_start = seg_ea
      is_next_cstring_end = True
      continue

    if driver_name in seg_name and '__text' in seg_name and text_start == None:
      text_start = seg_ea
      is_next_text_end = True
      continue

    if driver_name in seg_name and '__os_log' in seg_name and os_log_start == None:
      os_log_start = seg_ea
      is_next_os_log_end = True
      continue

  print("[+] Found needed segments:")
  print("  * text: 0x{:016x} - 0x{:016x}".format(text_start, text_end))
  print("  * cstring: 0x{:016x} - 0x{:016x}".format(cstring_start, cstring_end))
  print("  * os_log: 0x{:016x} - 0x{:016x}".format(os_log_start, os_log_end))
  return True


def is_os_log(ea):
  return os_log_start <= ea <= os_log_end


def is_cstring(ea):
  return cstring_start <= ea <= cstring_end


def count_xref_to(ea):
  return len(list(idautils.XrefsTo(ea)))


def get_func_addr_from_xref(ea):
  for xref in idautils.XrefsTo(ea):
    func = idaapi.get_func(xref.frm)
    return func.start_ea


def xref_is_func(ea):
  for xref in idautils.XrefsTo(ea):
    func = idaapi.get_func(xref.frm)
    if func == None:
      return False
    return True


def are_xrefs_only_from_one_func(ea):
  func_addr = None
  for xref in idautils.XrefsTo(ea):
    func = idaapi.get_func(xref.frm)
    if func == None:
      return False
    if func_addr == None:
      func_addr = func.start_ea
    elif func_addr == func.start_ea:
      continue
    else:
      return False
  return True


def is_ascii(s):
  return all(ord(c) < 128 for c in s)


def is_stringable(ea):
  xrefs = count_xref_to(ea)
  if xrefs == 0:
    return False
  elif xrefs == 1:
    return xref_is_func(ea)
  elif xrefs > 1:
    return are_xrefs_only_from_one_func(ea)


def main():
  if init() == False:
    return

  strs = idautils.Strings()
  strings = [s for s in strs if is_os_log(s.ea) or is_cstring(s.ea)]
  strings_list = [repr(str(s)) for s in strings]
  strings_counts = {repr(str(i)):strings_list.count(repr(str(i))) for i in strings}
  strings_uniqness = [i for i in strings_counts.keys() if strings_counts[i] == 1]

  def is_uniq(s):
    if repr(str(s)) in strings_uniqness: return True
    else: return False

  strings = [s for s in strs if (is_cstring(s.ea) or is_os_log(s.ea)) and is_uniq(s)]
  funcs = {}
  for s in strings:
    if is_ascii(str(s)) == False:
      continue
    if is_stringable(s.ea):
      func_addr = get_func_addr_from_xref(s.ea)
      func_name = ida_name.get_name(func_addr)
      if func_name.startswith('sub_'):
        continue
      if func_name not in funcs.keys():
        funcs[func_name] = {'type': 's', 'list': []}
      funcs[func_name]['list'].append(repr(str(s)))

  for f_ea in idautils.Functions(text_start, text_end):
    func_name_callee = ida_name.get_name(f_ea)
    if func_name_callee.startswith('sub_') == False and is_stringable(f_ea):
      func_addr_caller = get_func_addr_from_xref(f_ea)
      func_name_caller = ida_name.get_name(func_addr_caller)
      if func_name_caller.startswith('sub_'):
        continue
      if func_name_caller not in funcs.keys():
        funcs[func_name_caller] = {'type': 'f', 'list': []}
      if funcs[func_name_caller]['type'] == 'f':
        funcs[func_name_caller]['list'].append(func_name_callee)


  renamers = ""

  for f in funcs.keys():
    func_name = f
    rename_type = funcs[f]['type']
    list_of_strings = "["
    for s in funcs[f]['list']:
      if rename_type == "s":
        list_of_strings += "{:s},".format(s)
      else:
        list_of_strings += "\"{:s}\",".format(s)

    list_of_strings = list_of_strings[:-1]
    list_of_strings += "]"

    renamers += "    results.append(rename_func(\"{:s}\", \"{:s}\", {:s}))".format(func_name, rename_type, list_of_strings) + "\n"

    with open("{:s}.py".format(driver_name), 'w') as fdw:
      fdw.write(TEMPLATE.replace('__DRIVER_NAME__', driver_name).replace('__RENAME_FUNCS_LIST__', renamers))

main()
