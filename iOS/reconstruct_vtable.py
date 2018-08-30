import idc
import idaapi
import idautils


def add_struct_to_idb(name):
    idc.Til2Idb(-1, name)


def parse_demangled_name(str):
    class_name = str[0:str.find(':')]
    func_name = str[str.find(':')+2:str.find('(')]
    return [class_name,func_name]


def create_vtable_struct(class_name, functions):
    struct_name = 'vtable_' + class_name
    sid = idc.GetStrucIdByName(struct_name)
    if sid != BADADDR:
        print("vtable already exists for " + class_name)
        return 0
    
    sid = idc.AddStrucEx(-1, struct_name, 0)
    idc.Til2Idb(-1, struct_name)
    
    offset = 0
    for fn in functions:
        func_name = fn[0]
        func_name = func_name.replace('~', 'destr_')
        func_type = fn[1]

        idc.AddStrucMember(sid, func_name, -1, idc.FF_QWRD, -1, 8)
        if func_type != '':
            if func_type.find("__cdecl(") > -1:
                func_type = func_type.replace("__cdecl", "(__cdecl *%s)" % func_name)
            elif func_type.find("__stdcall(") > -1:
                func_type = func_type.replace("__stdcall", "(__stdcall *%s)" % func_name)
            elif func_type.find("__fastcall(") > -1:
                func_type = func_type.replace("__fastcall", "(__fastcall *%s)" % func_name)
            elif func_type.find("__thiscall(") > -1:
                func_type = func_type.replace("__thiscall", "(__thiscall *%s)" % func_name)
            elif func_type.find("__usercall(") > -1:
                func_type = func_type.replace("__usercall", "(__usercall *%s)" % func_name)
            elif func_type.find("__userpurge(") > -1:
                func_type = func_type.replace("__userpurge", "(__userpurge *%s)" % func_name)

            SetType(GetMemberId(sid, offset), func_type)
            # MakeComm(GetMemberId(sid, offset), func_name)
            # "__int64 (__fastcall *)(ClassName *this)");
        offset += 8
        print(fn)

    return 1   


def isVtable(addr):
    name = NameEx(BADADDR, addr)
    if name == '':
        return False
        
    dname = Demangle(name, 0)
    if dname and 'vtable' in dname:
        pass
    else:
        return False
        
    return True


def getClassNameFromVtable(addr):
    name = NameEx(BADADDR, addr)
    dname = Demangle(name, 0)
    return dname[12:]


def getStructNameForVtable(addr):
    return 'vtable_' + getClassNameFromVtable(addr)


def reconstruct_vtable(addr, vtable_name):
    # name = NameEx(BADADDR, addr)
    # if name == '':
    #     return 0
    # dname = Demangle(name, 0)
    # 
    # print(name)
    # print(dname)
    # vtable_name = ''
    # if dname and 'vtable' in dname:
    #     vtable_name = dname[12:]
    # else:
    #     print("Not vtable!!")
    #     return 0
    # 
    struct_name = 'vtable_' + vtable_name
    sid = idc.GetStrucIdByName(struct_name)
    if sid != BADADDR:
        print("struct " + struct_name + " already in base!")
        return 0

    
    print(vtable_name)

    start_addr = addr
    curr_addr = addr
    end_addr = 0
    has_function = False
    done = False
    functions = []
    fns = []

    while done == False:
        func = Qword(curr_addr)
        if func == 0:
            if has_function == False:
                func_name = 'anonymous'

                add_func = func_name
                i = 0
                while add_func in fns:
                    add_func = func_name + '_' + str(i)
                    i += 1

                functions.append([add_func,''])
                fns.append(add_func)
                curr_addr += 8
                continue
            else:
                done = True
                continue
        elif has_function == False:
            has_function = True

        func_addr = GetFunctionAttr(func, FUNCATTR_START)
        if func_addr == BADADDR:
            print('Non-Function in VTABLE!!!!')
            return 0
        
        func_name = GetFunctionName(func)
        func_type = GetType(func)
        if func_type == None:
            func_type = '__int64 __fastcall()'

        if func_name[0:3] == '__Z':
            func_name = Demangle(func_name,0)
            class_name, func_name = parse_demangled_name(func_name)
            
            if class_name != vtable_name:
                func_name = class_name + '::' + func_name

        add_func = func_name
        i = 0
        while add_func in fns:
            add_func = func_name + '_' + str(i)
            i += 1

        functions.append([add_func, func_type])
        fns.append(add_func)
        curr_addr += 8

    if create_vtable_struct(vtable_name, functions):
        SetType(addr, 'struct vtable_' + vtable_name)
         
    
addr = ScreenEA()
if isVtable(addr):
    struct_name = getClassNameFromVtable(addr)
    reconstruct_vtable(addr, struct_name)
