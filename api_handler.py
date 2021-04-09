# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from unicorn.unicorn_const import UC_ARCH_ARM64, UC_ARCH_X86
from unicorn.x86_const import UC_X86_REG_XMM0, UC_X86_REG_XMM1, UC_X86_REG_XMM2, UC_X86_REG_XMM3
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EIP
import struct

from speakeasy_origin.struct import EmuStruct
import speakeasy_origin.windef.windows.com as winemu
import speakeasy.winenv.defs.nt.ntoskrnl as ntos
from pydll import DLL_BASE

from keystone import * # using keystone as assembler
from capstone import * # using capstone as disassembler

class CALL_CONV:
    CALL_CONV_CDECL = 0
    CALL_CONV_STDCALL = 1
    CALL_CONV_FASTCALL = 2
    CALL_CONV_FLOAT = 3
    VAR_ARGS = -1


class ApiHandler(object):
    """
    Base class for handling exported functions
    """

    name = ''


    @staticmethod
    def call_api(emu, args, ctx, api):
        api(emu, args, ctx)

    @staticmethod
    def get_argv(emu, call_conv, argc, arch=UC_ARCH_X86, ptr_size=4):
        """
        Get the arguments for a function given the supplied calling convention
        """
        argv = []
        ptr_size = ptr_size
        arch = arch
        nargs = argc
        endian = 'little'
        
        # Handle calling conventions using floats
        sp = emu.uc_eng.reg_read(UC_X86_REG_ESP)
        if arch in (UC_ARCH_X86, UC_ARCH_ARM64):
            if call_conv == CALL_CONV.CALL_CONV_FLOAT:
                for r in enumerate(UC_X86_REG_XMM0,UC_X86_REG_XMM1,UC_X86_REG_XMM2,UC_X86_REG_XMM3):
                    if nargs == 0:
                        break
                    val = emu.uc_eng.reg_read(r)
                    argv.append(val)
                    nargs -= 1

        if arch == UC_ARCH_X86:
            if call_conv == CALL_CONV.CALL_CONV_FASTCALL:
                if nargs >= 2:
                    argv.append(emu.uc_eng.reg_read(UC_X86_REG_ECX))
                    argv.append(emu.uc_eng.reg_read(UC_X86_REG_EDX))
                    nargs -= 2
                elif nargs == 1:
                    argv.append(emu.uc_eng.reg_read(UC_X86_REG_ECX))
                    nargs -= 1
        else:
            raise Exception("Unsupported architecture")

        # Skip past the saved ret addr
        sp += ptr_size
        for i in range(nargs):
            ptr = emu.uc_eng.mem_read(sp, ptr_size)
            argv.append(int.from_bytes(ptr, endian))
            sp += ptr_size

        return argv    

    @staticmethod
    def get_ret_addr(argc, ptr_size, arch, emu):
        if arch == UC_ARCH_X86:
            ra = emu.uc_eng.mem_read((ptr_size * argc), ptr_size)
        else:
            raise Exception('Unsupported architecture')

        return ra

    @staticmethod
    def api_call_cb_wrapper(self, uc, addr, size, d):
        emu, arch, ptr_size = d
        print(hex(addr))
        sp = uc.reg_read(UC_X86_REG_ESP) # stack pointer
        args = struct.unpack('<IIIIII', uc.mem_read(sp, 24))
        
        CODE = uc.mem_read(addr, size)
        
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        for i in md.disasm(bytes(CODE), addr):
            print("%x:%s%s\t%s" %(i.address, 2 * '\t', i.mnemonic, i.op_str))

        for i in range(1, 5):
            strval = emu.uc_eng.mem_read(args[i], 30).decode('utf8', errors='ignore').strip('\x00')
            print('>>> args_%i(%x) --> %.8x | %s' % (i, sp + 4 * i, args[i], strval))
        print('---------------------------------------------------------\n')


        if addr < DLL_BASE:
            pass
        else:
            if addr in emu.imp:
                dll, api = emu.imp[addr] # (str, str)
                pyDLL:ApiHandler = emu.mods.get(dll)
                if not pyDLL:
                    emu.load_library(dll)
                    pyDLL:ApiHandler = emu.mods.get(dll)
                api_attributes = getattr(pyDLL, api)
                handler_name, _api, argv, conv, ordinal = api_attributes
                ret_addr = ApiHandler.get_ret_addr(len(argv), ptr_size, arch, emu)
                argv = ApiHandler.get_argv(emu, conv, argv, arch, self.ptr_size)
                ApiHandler.call_api(emu, argv, {}, _api)
                self.ret_procedure(argv, ret_addr, None, conv)
            else:
                raise Exception("Invalid memory access")

    @staticmethod
    def api_set_schema(name):
        ret = name

        if name.lower().startswith(('api-ms-win-crt', 'msvcp1','vcruntime', 'ucrtbased', 'ucrtbase')): # Runtime DLL
            ret = 'msvcrt'

        # Redirect windows sockets 1.0 to windows sockets 2.0
        elif name.lower().startswith(('winsock', 'wsock32')):
            ret = 'ws2_32'

        elif name.lower().startswith('api-ms-win-core'): # VirtualDLL
            ret = 'kernel32'

        return ret

    @staticmethod
    def api_call(impname=None, argc=0, conv=CALL_CONV.CALL_CONV_STDCALL, ordinal=None):

        def api_call_wrapper(f):
            if not callable(f):
                raise Exception('Invalid function type supplied: %s' % (str(f)))
            f.__apicall__ = (impname or f.__name__, f, argc, conv, ordinal)
            return f

        return api_call_wrapper

    @staticmethod
    def get_char_width(ctx):
        """
        Based on the API name, determine the character width
        being used by the function
        """
        name = ctx.get('func_name', '')
        if name.endswith('A'):
            return 1
        elif name.endswith('W'):
            return 2
        raise Exception('Failed to get character width from function: %s' % (name))

    @staticmethod
    def get_api_name(func):
        return func.__apicall__[0]

    def __init__(self, emu):
        super(ApiHandler, self).__init__()
        self.funcs = {}
        self.data = {}
        self.mod_name = ''
        self.emu = emu
        self.arch = self.emu.get_arch()
        self.ptr_size = self.emu.get_ptr_size() # x86 only

        

        for name in dir(self):
            val = getattr(self, name, None)
            if val is None:
                continue

            func_attrs = getattr(val, '__apicall__', None)
            data_attrs = getattr(val, '__datahook__', None)
            if func_attrs:
                name, func, argc, conv, ordinal = func_attrs
                self.funcs[name] = (name, func, argc, conv, ordinal)
                if ordinal:
                    self.funcs[ordinal] = (name, func, argc, conv, ordinal)

            elif data_attrs:
                name, func = data_attrs
                self.data[name] = func

    def get_ptr_size(self):
        return self.ptr_size

    def arrange_stack(self, argc):
        """
        Adjust the stack for arguments that were supplied
        """
        ptr_size = self.ptr_size
        arch = self.arch

        if argc == 0:
            return

        if arch == UC_ARCH_X86:
            sp = self.emu.uc_eng.reg_read(UC_X86_REG_ESP)
            sp += (ptr_size * argc)
            self.emu.uc_eng.reg_write(UC_X86_REG_ESP, sp)

        else:
            raise Exception('Unsupported architecture')

    def recov_ret(self, ret_addr):
        self.emu.uc_eng.reg_write(UC_X86_REG_EIP, ret_addr)
        pass

    def ret_procedure(self, argc, ret_addr=None, ret_value=None, conv=CALL_CONV.CALL_CONV_STDCALL):
        """
        Set the emulation state after a call has completed
        """
        if self.arch == UC_ARCH_X86:
            rv = UC_X86_REG_EAX
        else:
            raise Exception('Unsupported architecture')

        if conv == CALL_CONV.CALL_CONV_FLOAT:
            rv = UC_X86_REG_XMM0

        _esp = self.emu.uc_eng.reg_read(UC_X86_REG_ESP)

        if ret_addr:
            self.emu.uc_eng.reg_write(UC_X86_REG_ESP, _esp + self.ptr_size)
            self.recov_ret(ret_addr)
        else:
            raise Exception('Envalid return address')

        if ret_value is not None:
            self.emu.uc_eng.reg_write(rv, ret_value)

        # Cleanup the stack
        if conv == CALL_CONV.CALL_CONV_CDECL:
            # If cdecl, the emu engine will clean the stack
            pass
        elif conv == CALL_CONV.CALL_CONV_FASTCALL:
            if self.arch == UC_ARCH_X86:
                if argc > 2:
                    self.arrange_stack(argc-2)
        else:
            self.arrange_stack(argc)

    def __get_api_attrs__(self, obj):
        for name in dir(obj):
            val = getattr(obj, name, None)
            if val is None:
                continue

            func_attrs = getattr(val, '__apicall__', None)
            data_attrs = getattr(val, '__datahook__', None)
            if func_attrs:
                name, func, argc, conv, ordinal = func_attrs
                obj.funcs[name] = (name, func, argc, conv, ordinal)
                if ordinal:
                    obj.funcs[ordinal] = (name, func, argc, conv, ordinal)

            elif data_attrs:
                name, func = data_attrs
                obj.data[name] = func

    
    def get_va_arg_count(self, fmt):
        """
        Get the number of arguments in the variable argument list
        """

        # Ignore escapes
        i = fmt.count('%%')
        c = fmt.count('%')

        if self.get_ptr_size() != 8:
            c += fmt.count('%ll')
        return c - i

    def va_args(self, va_list, num_args):
        """
        Get the variable argument list
        """
        args = []
        ptr = va_list
        ptrsize = self.get_ptr_size()

        for n in range(num_args):
            arg = int.from_bytes(self.emu.mem_read(ptr, ptrsize), 'little')
            args.append(arg)
            ptr += ptrsize
        return args
