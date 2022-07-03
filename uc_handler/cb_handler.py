# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import struct

from common import read_mem_string
from unicorn.unicorn_const import UC_ARCH_ARM64, UC_ARCH_X86, UC_MEM_WRITE
from unicorn.x86_const import *

from pydll import DLL_BASE
from keystone import * # using keystone as assembler
from capstone import * # using capstone as disassembler

from colorama import Fore, Back, Style


def logger(uc, addr, size, d):
    def ReadRegister(uc):
        _eip = uc.reg_read(UC_X86_REG_EIP)
        _eax = uc.reg_read(UC_X86_REG_EAX)
        _ebx = uc.reg_read(UC_X86_REG_EBX)
        _ecx = uc.reg_read(UC_X86_REG_ECX)
        _edx = uc.reg_read(UC_X86_REG_EDX)
        _esi = uc.reg_read(UC_X86_REG_ESI)
        _edi = uc.reg_read(UC_X86_REG_EDI)
        _esp = uc.reg_read(UC_X86_REG_ESP)
        _ebp = uc.reg_read(UC_X86_REG_EBP)

        return _eip, _eax, _ebx, _ecx, _edx, _esi, _edi, _esp, _ebp
    
    _eip, _eax, _ebx, _ecx, _edx, _esi, _edi, _esp, _ebp = ReadRegister(uc)
    _bin = uc.mem_read(_eip, 10)

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for op in md.disasm(_bin, addr):
        disas = op.mnemonic + " " + op.op_str
        break

    try:
        _esi_var = uc.mem_read(_esi, 30).split(b"\x00")[0].decode('utf8', errors='ignore').strip(
            '\x00')
        _edi_var = uc.mem_read(_edi, 30).split(b"\x00")[0].decode('utf8', errors='ignore').strip(
            '\x00')
    except:
        _esi_var = ""
        _edi_var = ""

    stack_arr = []
    pStack_arr = []
    for i in range(0, 5):
        esp = uc.reg_read(UC_X86_REG_ESP) + (4 * i)
        saved_val = struct.unpack("<L", uc.mem_read(esp, 4))[0]
        stack_arr.append(esp)
        pStack_arr.append(saved_val)

    print("------------------------------------------------------------------------------------------------")
    print(("EIP : 0x%-8x      \033[1;31m%-30s\x1b[0m                                  \033[96m%-10s\x1b[0m" % (_eip, disas, "Stack")))
    print(("ESP : 0x%-8x      EBP : 0x%-8x                                              | \033[96m0x%-8x : 0x%-8x\x1b[0m" % (_esp, _ebp, stack_arr[0], pStack_arr[0])))
    print(("EAX : 0x%-8x      EBX : 0x%-8x      ECX : 0x%-8x      EDX : 0x%-8x  | \033[96m0x%-8x : 0x%-8x\x1b[0m" % (_eax, _ebx, _ecx, _edx, stack_arr[1], pStack_arr[1])))
    print(("ESI : 0x%-8x      ---------->     %-11s                                    | \033[96m0x%-8x : 0x%-8x\x1b[0m" % (_esi, _esi_var, stack_arr[2], pStack_arr[2])))
    print(("EDI : 0x%-8x      ---------->     %-10s                                    | \033[96m0x%-8x : 0x%-8x\x1b[0m" % (_edi, _edi_var, stack_arr[3], pStack_arr[3])))

    pass