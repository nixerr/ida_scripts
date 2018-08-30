import idc
import idautils
import idaapi

def rename_got(t):
    func = False
    name = ''
    i = 0

    # print(GetType(t))

    OpOff(t, 0, 0)
    addr = Qword(t)

    if not idaapi.get_func(addr):
        print("0x%X is not function" % (addr))
        name = NameEx(addr,addr)
        if name != '':
            print("Name = " + name)
            i = 0
            nname = name + '_' + str(i)
            while not MakeNameEx(t, nname, SN_NOWARN):
                i += 1
                nname = name + '_' + str(i)
    else:
        func = True
        name = GetFunctionName(addr)
        type = GetType(addr)
        if 'sub_' in name:
            print("This isn't global known function!")
        else:
            print("Name = " + name)
            nname = name + '_' + str(i)
            while not MakeNameEx(t, nname, SN_NOWARN):
                i += 1
                nname = name + '_' + str(i)
                
    
    
        if type == None and name == '__ZN15OSMetaClassBase12safeMetaCastEPKS_PK11OSMetaClass':
            type = '__int64 __fastcall(OSMetaClassBase *__hidden this, const OSMetaClassBase *, const OSMetaClass *)'
        if type == None and name == '__Z21IODTResolveAddressingP15IORegistryEntryPKcP14IODeviceMemory':
            type = '__int64 __fastcall(IORegistryEntry *, const char *, IODeviceMemory *)'
        if type != None:
            print("Type = " + type)
            if '__fastcall(' in type:
                type = type.replace('__fastcall', '(*' + name + ')')
            elif '__cdecl(' in type:
                type = type.replace('__cdecl', '(*' + name + ')')
            else:
                type = type[0:type.find('(')] + '(*' + name + ')' + type[type.find('('):]
            SetType(t, type)
        else:
            print("Type is None!!!")

    xref = DfirstB(t)
    if (xref != 0xffffffffffffffff):
        print("Xref = " + hex(xref))
        if '__stubs' in get_segm_name(xref) and func == True:
            print("Has pointer from __stubs... Renaming")
            i += 1
            nname = name + '_' + str(i)
            while not MakeNameEx(xref, nname, SN_NOWARN):
                i += 1
                nname = name + '_' + str(i)


t = idc.get_screen_ea()
rename_got(t) 
