# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from speakeasy_origin.struct import EmuStruct
import speakeasy_origin.windef.windows.com as winemu

import speakeasy.winenv.defs.nt.ntoskrnl as ntos

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
    def normalize_dll_name(name):
        ret = name

        # Funnel CRTs into a single handler
        if name.lower().startswith(('api-ms-win-crt', 'vcruntime', 'ucrtbased', 'ucrtbase')):
            ret = 'msvcrt'

        # Redirect windows sockets 1.0 to windows sockets 2.0
        elif name.lower().startswith(('winsock', 'wsock32')):
            ret = 'ws2_32'

        elif name.lower().startswith('api-ms-win-core'):
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
        arch = self.emu.get_arch()

        self.ptr_size = 4 # x86 only

        

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

    def setup_callback(self, func, args, caller_argv=[]):
        """
        For APIs that call functions, we will setup the stack to make this flow
        naturally.
        """

        run = self.emu.get_current_run()

        if not len(run.api_callbacks):
            # Get the original return address
            ret = self.emu.get_ret_address()
            sp = self.emu.get_stack_ptr()

            self.emu.set_func_args(sp, winemu.API_CALLBACK_HANDLER_ADDR, *args)
            self.emu.set_pc(func)
            run.api_callbacks.append((ret, func, caller_argv))
        else:
            run.api_callbacks.append((None, func, args))
