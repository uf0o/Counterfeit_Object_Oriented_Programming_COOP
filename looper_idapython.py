import idautils 
# COOP gadget finder IDAPython
 
def find_text_segment():
    # finds .text section start and end addresses
    for seg in Segments():
        segment_name = idc.get_segm_name(seg)
        if (segment_name == ".text"):
            start = idc.get_segm_start(seg)
            end   = idc.get_segm_end(seg)
            print("%s section: 0x%x - 0x%x" % (idc.get_segm_name(seg), idc.get_segm_start(seg),idc.get_segm_end(seg)))
            return start,end  

def find_loader_reg_vfgadget(reg,max_length,constrained):
    # scan .text segments for functions and start and end address
    valid_functions = []
    text_start,text_ends = find_text_segment()   
    for func in Functions(text_start,text_end):
        first_instruction = True
        flags = idc.get_func_attr(func,FUNCATTR_FLAGS)
        #checks if the function has no ret or is a thunk
        if flags & FUNC_NORET or flags & FUNC_THUNK:                  
            #print("0x%x FUNC_NORET" % func)
            continue
        # disasm starts
        dism_addr = list(FuncItems(func))
        func = idaapi.get_func(func)
        func_name = idc.get_func_name(func.start_ea)
        func_start = func.start_ea
        func_ends = func.end_ea
        last_instruction = dism_addr.pop()
        for line in (dism_addr):  
            if len(dism_addr) > max_length:             # max nr of instructions per function
                break
            ins = ida_ua.insn_t() 
            idaapi.decode_insn(ins, line)
            #if first instruction not a 'mov' and last one is not a ret we bail out
            if (first_instruction and ins.itype != 0x7a): # 7a = mov
                break
            if "ret" not in idc.generate_disasm_line(last_instruction, 0):
                break
            # if constrain is set , it discard any function that mangles the target reg after 1st line
            if constrained  and (not first_instruction and (reg in idc.print_operand(line,0))): 
                if func_name in valid_functions: valid_functions.remove(func_name)
                break
            else:
                first_instruction = False
                idc.print_insn_mnem(ea)
                # check the first operand is a reg and second a disposition
                if ins.Op1.type == o_reg and ins.Op2.type == o_displ:
                    if (idc.print_operand(line,0) == reg or  idc.print_operand(line,0) == reg+"d") and ("rcx+" in idc.print_operand(line,1)):
                        #print("0x%x, %s" % (func_start, func_name ))
                        #print("0x%x %s" % (line, idc.generate_disasm_line(line, 0)))
                        #print("0x%x %s" % (last_instruction , idc.generate_disasm_line(last_instruction, 0)))
                        valid_functions.append(func_name)
    for func in valid_functions:
        print(func)
    return valid_functions           

def find_looper_vfgadget(max_length):
    # scan .text segments for functions and start and end address
    valid_functions = []
    text_start,text_ends = find_text_segment()   
    for func in Functions(text_start,text_end):
        first_instruction = True
        flag1 = False
        flag2 = False
        flag3 = False
        flag4 = False
        flags = idc.get_func_attr(func,FUNCATTR_FLAGS)
        #checks if the function has no ret or is a thunk
        if flags & FUNC_NORET or flags & FUNC_THUNK:                  
            #print("0x%x FUNC_NORET" % func)
            continue
        # disasm starts
        dism_addr = list(FuncItems(func))
        func = idaapi.get_func(func)
        func_name = idc.get_func_name(func.start_ea)
        func_start = func.start_ea
        func_ends = func.end_ea
        last_instruction = dism_addr.pop()
        for line in (dism_addr):  
            if flag1 and flag2 and flag3 and flag4:
                valid_functions.append(func_name)
                break
            if len(dism_addr) > max_length:             # max nr of instructions per function
                break
            ins = ida_ua.insn_t() 
            idaapi.decode_insn(ins, line)
            #if first instruction not a 'mov' and last one is not a ret we bail out
            if (first_instruction and ins.itype != 0x7a): # 7a = mov
                break
            if "ret" not in idc.generate_disasm_line(last_instruction, 0):
                break
            else:
                first_instruction = False
                idc.print_insn_mnem(ea)
                # check the first operand is a reg and second a disposition
                if ins.Op1.type == o_reg and ins.Op2.type == o_displ:
                    if (idc.print_operand(line,0) == "rbx") and ("rcx" in idc.print_operand(line,1)):
                        flag1 = True
                if idc.print_insn_mnem(line) == "call" and not ("__guard_dispatch_icall_fptr" in idc.print_operand(line,0)):
                    break
                if idc.print_insn_mnem(line) == "call" and ("__guard_dispatch_icall_fptr" in idc.print_operand(line,0)):
                    call_address = int(line)
                    #print("0x%x" % call_address)
                    flag2 = True
                if idc.print_insn_mnem(line) == "jnz":
                    jmp_operand_address = idc.print_operand(line,0)
                    jmp_to_address = int(idc.get_name_ea_simple(jmp_operand_address))
                    #print("0x%x" % jmp_to_address)
                    flag3 = True
                if flag3 and flag2:
                    if jmp_to_address < call_address:
                        flag4 = True   
    for func in valid_functions:
        print(func)
    print("\nTotal valid_functions: %d \n" % len(valid_functions))
    return valid_functions 
    


constrained = False
"""
print("\n[*] Finding 'RCX-loader' vfgadgets")
find_loader_reg_vfgadget("rcx",0xf,False)
print("\n[*] Finding 'RDX-loader' vfgadgets")
find_loader_reg_vfgadget("rdx",0xf,False)
print("\n[*] Finding 'R8-loader' vfgadgets")
find_loader_reg_vfgadget("r8",0xf,False)
print("\n[*] Finding 'R9-loader' vfgadgets")
find_loader_reg_vfgadget("r9",0xf,False)
"""
print("\n[*] Finding 'loopers' vfgadgets")
find_looper_vfgadget(0x30)
