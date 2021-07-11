# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from common import read_mem_string
import functools
from emu_handler import EmuHandler
from operator import add
from unicorn.unicorn_const import UC_ARCH_ARM64, UC_ARCH_X86, UC_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_XMM0, UC_X86_REG_XMM1, UC_X86_REG_XMM2, UC_X86_REG_XMM3
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EIP
from unicorn.x86_const import UC_X86_REG_EBP, UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_FS, UC_X86_REG_GS, UC_X86_REG_SS, UC_X86_REG_EFLAGS
import struct

from speakeasy_origin.struct import EmuStruct
import speakeasy_origin.windef.windows.com as winemu
import speakeasy.winenv.defs.nt.ntoskrnl as ntos
from pydll import DLL_BASE

from keystone import * # using keystone as assembler
from capstone import * # using capstone as disassembler

from colorama import Fore, Back, Style

class CALL_CONV:
    CALL_CONV_CDECL = 0
    CALL_CONV_STDCALL = 1
    CALL_CONV_FASTCALL = 2
    CALL_CONV_FLOAT = 3
    VAR_ARGS = -1

class Dispatcher(object):
    mmf_counter_tab = {}
    @staticmethod
    def file_map_dispatcher(uc, address, size , d):
        # Dispatching all memory region for every 10 times instruction

        emu, mmf_obj = d

        if Dispatcher.mmf_counter_tab[mmf_obj.handle] < 10:
            Dispatcher.mmf_counter_tab[mmf_obj.handle] += 1
            pass
    
        Dispatcher.mmf_counter_tab[mmf_obj.handle] = 0

        view_base = mmf_obj.get_view_base()
        map_max = mmf_obj.map_max

        data = uc.mem_read(view_base, map_max) # Fixing the dispatch size as map_max may occur error.
        emu.fs_manager.write_file(mmf_obj.file_handle, data)

        emu.fs_manager.set_file_pointer(
                mmf_obj.file_handle, 
                mmf_obj.get_file_offset()
            )


class CodeCBHandler(object):
    @staticmethod
    def unmap_handler(uc, access, addr, size, value, d):
        emu, arch, ptr_size = d
        print(hex(addr), hex(value))
        pass
        
    @staticmethod
    def logger(uc, addr, size, d):
        def ReadRegister(emu):
            
            
            _eip = emu.uc_eng.reg_read(UC_X86_REG_EIP)
            _eax = emu.uc_eng.reg_read(UC_X86_REG_EAX)
            _ebx = emu.uc_eng.reg_read(UC_X86_REG_EBX)
            _ecx = emu.uc_eng.reg_read(UC_X86_REG_ECX)
            _edx = emu.uc_eng.reg_read(UC_X86_REG_EDX)
            _esi = emu.uc_eng.reg_read(UC_X86_REG_ESI)
            _edi = emu.uc_eng.reg_read(UC_X86_REG_EDI)
            _esp = emu.uc_eng.reg_read(UC_X86_REG_ESP)
            _ebp = emu.uc_eng.reg_read(UC_X86_REG_EBP)

            return _eip, _eax, _ebx, _ecx, _edx, _esi, _edi, _esp, _ebp

        emu, arch, ptr_size = d
        
        _eip, _eax, _ebx, _ecx, _edx, _esi, _edi, _esp, _ebp = ReadRegister(emu=emu)
        _bin = emu.uc_eng.mem_read(_eip, 10)

        md = Cs(CS_ARCH_X86, CS_MODE_32)
        for op in md.disasm(_bin, addr):
            disas = op.mnemonic + " " + op.op_str
            break

        try:
            _esi_var = emu.uc_eng.mem_read(_esi, 30).split(b"\x00")[0].decode('utf8', errors='ignore').strip(
                '\x00')
            _edi_var = emu.uc_eng.mem_read(_edi, 30).split(b"\x00")[0].decode('utf8', errors='ignore').strip(
                '\x00')
        except:
            _esi_var = ""
            _edi_var = ""

        stack_arr = []
        pStack_arr = []
        for i in range(0, 5):
            esp = emu.uc_eng.reg_read(UC_X86_REG_ESP) + (4 * i)
            saved_val = struct.unpack("<L", emu.uc_eng.mem_read(esp, 4))[0]
            stack_arr.append(esp)
            pStack_arr.append(saved_val)

        print("------------------------------------------------------------------------------------------------")
        print(("EIP : 0x%-8x      \033[1;31m%-30s\x1b[0m                                  \033[96m%-10s\x1b[0m" % (_eip, disas, "Stack")))
        print(("ESP : 0x%-8x      EBP : 0x%-8x                                              | \033[96m0x%-8x : 0x%-8x\x1b[0m" % (_esp, _ebp, stack_arr[0], pStack_arr[0])))
        print(("EAX : 0x%-8x      EBX : 0x%-8x      ECX : 0x%-8x      EDX : 0x%-8x  | \033[96m0x%-8x : 0x%-8x\x1b[0m" % (_eax, _ebx, _ecx, _edx, stack_arr[1], pStack_arr[1])))
        print(("ESI : 0x%-8x      ---------->     %-11s                                    | \033[96m0x%-8x : 0x%-8x\x1b[0m" % (_esi, _esi_var, stack_arr[2], pStack_arr[2])))
        print(("EDI : 0x%-8x      ---------->     %-10s                                    | \033[96m0x%-8x : 0x%-8x\x1b[0m" % (_edi, _edi_var, stack_arr[3], pStack_arr[3])))

        pass

class ApiHandler(object):
    """
    Base class for handling exported functions
    """

    name = ''

    @staticmethod
    def call_api(obj, emu, args, ctx, api):
        ret_val = api(obj, emu, args, ctx)

        return ret_val

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
    def arrange_stack(argc, d):
        """
        Adjust the stack for arguments that were supplied
        """
        emu, ptr_size, arch = d

        if argc == 0:
            return

        if arch == UC_ARCH_X86:
            sp = emu.uc_eng.reg_read(UC_X86_REG_ESP)
            sp += (ptr_size * argc)
            emu.uc_eng.reg_write(UC_X86_REG_ESP, sp)

        else:
            raise Exception('Unsupported architecture')
            
    @staticmethod
    def recov_ret(ret_addr, emu):
        if isinstance(ret_addr, bytes) or isinstance(ret_addr, bytearray):
            ret_addr = struct.unpack("<I", ret_addr)[0]
        emu.uc_eng.reg_write(UC_X86_REG_EIP, ret_addr)
        pass

    @staticmethod
    def ret_procedure(argc, d, ret_addr=None, ret_value=None, conv=CALL_CONV.CALL_CONV_STDCALL):
        """
        Set the emulation state after a call has completed
        """
        emu, arch, ptr_size = d
        if arch == UC_ARCH_X86:
            rv = UC_X86_REG_EAX
        else:
            raise Exception('Unsupported architecture')

        if conv == CALL_CONV.CALL_CONV_FLOAT:
            rv = UC_X86_REG_XMM0

        _esp = emu.uc_eng.reg_read(UC_X86_REG_ESP)

        if ret_addr:
            emu.uc_eng.reg_write(UC_X86_REG_ESP, _esp + ptr_size)
            ApiHandler.recov_ret(ret_addr, emu)
        else:
            raise Exception('Envalid return address')

        if ret_value is not None:
            emu.uc_eng.reg_write(rv, ret_value)

        # Cleanup the stack
        if conv == CALL_CONV.CALL_CONV_CDECL:
            # If cdecl, the emu engine will clean the stack
            pass
        elif conv == CALL_CONV.CALL_CONV_FASTCALL:
            if arch == UC_ARCH_X86:
                if argc > 2:
                    ApiHandler.arrange_stack(argc-2, d)
        else:
            ApiHandler.arrange_stack(argc, d)

    @staticmethod
    def get_ret_addr(argc, ptr_size, arch, proc):
        if arch == UC_ARCH_X86:
            _esp = proc.uc_eng.reg_read(UC_X86_REG_ESP)
            ra = proc.uc_eng.mem_read(_esp, ptr_size)
        else:
            raise Exception('Unsupported architecture')

        return ra

    @staticmethod
    def set_thread_args(emu, ebp, ret_addr, pArgs, arch=UC_ARCH_X86, ptr_size=4):
        _ebp = ebp
        if pArgs is None:
            pArgs = 0
        emu.uc_eng.mem_write(_ebp+4, ret_addr.to_bytes(4, "little"))
        emu.uc_eng.mem_write(_ebp+8, pArgs.to_bytes(4, "little"))

    @staticmethod
    def set_func_args(emu, stack_addr, ret_addr, *args, arch=UC_ARCH_X86, ptr_size=4):
        """
        Set the arguments before an emulated function call. This is how we pass
        arguments to a function when calling it through the emulator.
        """
        curr_sp = stack_addr - ptr_size
        if args[0] == None:
            nargs = 0
        else:
            nargs = len(args)

        if arch == UC_ARCH_X86:
            sp = UC_X86_REG_ESP
        else:
            raise Exception("Unsupported architecture")

        if nargs > 0:
            for arg in args[-nargs:][::-1]:
                a = arg.to_bytes(ptr_size, byteorder='little')
                emu.uc_eng.mem_write(curr_sp, a)
                emu.uc_eng.reg_write(sp, curr_sp)
                curr_sp -= ptr_size

        # Set the return address
        r = ret_addr.to_bytes(ptr_size, byteorder='little')
        emu.uc_eng.mem_write(curr_sp, r)
        emu.uc_eng.reg_write(sp, curr_sp)

    @staticmethod
    def log_api_info(p, api_name):
        if api_name in p.emu.winapi_info_dict:
            print(Fore.LIGHTRED_EX + api_name)
            api_info = p.emu.winapi_info_dict[api_name]
            arg_idx = 0
            for arg_type in api_info["args_types"]:
                arg_idx+=1
                arg_raw = int.from_bytes(p.uc_eng.mem_read(p.uc_eng.reg_read(UC_X86_REG_ESP) + (4 * (arg_idx)), 4), "little")
                arg = ""
                if "wchar*" in arg_type:
                    arg = read_mem_string(p.uc_eng, arg_raw, 2, 50)
                elif "char*" in arg_type:
                    arg = read_mem_string(p.uc_eng, arg_raw, 1, 50)
                else:
                    arg = str(hex(arg_raw))
                if arg:
                    if arg[-1] == "\n":
                        arg = arg[:-1]
                else:
                    arg = "NULL"
                print(Fore.BLUE+"  "+"["+arg_type+"]"+" > " + arg)
        else:
            print(Fore.LIGHTRED_EX + api_name + "\tcalled")
        pass

    @staticmethod
    def pre_api_call_cb_wrapper(uc, addr, size, d):
        proc, arch, ptr_size = d
        '''
        if not emu.running:
            uc.emu_stop()
            EmuHandler.emu_q.remove((emu.pid, emu))
            return
        '''
        if proc.emu_suspend_flag:
            proc.uc_eng.emu_stop()
            return

        if addr >= DLL_BASE:
            if addr in proc.api_va_dict:
                ctx={}
                dll, api = proc.api_va_dict[addr] # (str, str)
                pyDLL:ApiHandler = proc.e_dllobj.get(dll)
                api_name = api
                if not pyDLL:
                    proc.emu.load_library(dll)
                    pyDLL:ApiHandler = proc.e_dllobj.get(dll)
                if api.endswith('A') or api.endswith('W'):
                    ctx["func_name"] = api
                    api = api[:-1]
                api_attributes = ApiHandler.__get_api_attrs(pyDLL, api)
                if not api_attributes:
                    proc.uc_eng.emu_stop()
                    raise Exception("Not implemented api [%s --> %s]" % (dll, api))

                handler_name, _api, argc, conv, ordinal = api_attributes
                ApiHandler.log_api_info(proc, api_name)
                ret_addr = ApiHandler.get_ret_addr(argc, ptr_size, arch, proc)
                argv = ApiHandler.get_argv(proc, conv, argc, arch, proc.emu.ptr_size)
                ret_val = ApiHandler.call_api(pyDLL, proc, argv, ctx, _api)
                ApiHandler.ret_procedure(argc, (proc, arch, ptr_size), ret_addr, ret_val, conv)
                proc.api_call_flag = (True, proc.uc_eng.reg_read(UC_X86_REG_EIP))
                return
            else:
                raise Exception("Invalid memory access")
        else:
            if not proc.api_call_flag[0]:
                proc.api_call_flag = (False, None)
    
    @staticmethod
    def post_api_call_cb_wrapper(uc, addr, size, d):
        proc, (params), number_of_args, cb = d
        f, eip = proc.api_call_flag
        if f and proc.uc_eng.reg_read(UC_X86_REG_EIP) != eip:
            r = cb(*params)
            # r = cb_wrapper(cb, params)
            proc.api_call_flag = (False, None)
            return r
        else:
            return None

    @staticmethod
    def api_set_schema(name):
        ret = name

        if name.lower().startswith(('api-ms-win-crt', 'msvcp1','vcruntime', 'ucrtbased', 'ucrtbase', 'msvcr')): # Runtime DLL
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
    def __get_api_attrs(dll, api):
        if api in dll.funcs:
            return dll.funcs[api]
        else:
            return None

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

    def __init__(self, proc_obj):
        super(ApiHandler, self).__init__()
        self.funcs = {}
        self.data = {}
        self.mod_name = ''
        self.proc = proc_obj
        self.arch = proc_obj.get_arch()
        self.ptr_size = proc_obj.get_ptr_size()

    def get_ptr_size(self):
        return self.ptr_size

    def __set_api_attrs__(self, obj):
        for name in dir(obj):
            val = getattr(obj, name, None)
            if val is None:
                continue

            func_attrs = getattr(val, '__apicall__', None)
            if func_attrs:
                name, func, argc, conv, ordinal = func_attrs
                obj.funcs[name] = (name, func, argc, conv, ordinal)
                if ordinal:
                    obj.funcs[ordinal] = (name, func, argc, conv, ordinal)
            
        pass

    def get_va_arg_count(self, fmt):
        """
        Get the number of arguments in the variable argument list
        """

        # Ignore escapes
        i = fmt.count('%%')
        c = fmt.count('%')

        if self.ptr_size != 8:
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
            arg = int.from_bytes(self.proc.uc_eng.mem_read(ptr, ptrsize), 'little')
            args.append(arg)
            ptr += ptrsize
        return args

    def va_args2(self, num_args): # <-- Works only X86?
        """
        Get the variable argument list
        """
        args = []
        ptr = self.proc.uc_eng.reg_read(UC_X86_REG_ESP)+(num_args+1)*self.ptr_size
        ptrsize = self.ptr_size

        for n in range(num_args):
            arg = int.from_bytes(self.proc.uc_eng.mem_read(ptr, ptrsize), 'little')
            args.append(arg)
            ptr += ptrsize
        return args