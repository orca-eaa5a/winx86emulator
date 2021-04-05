import math
import struct

import speakeasy.winenv.defs.windows.windows as windef
from api_handler import CALL_CONV as cv
from api_handler import ApiHandler
from windef.mem_defs import PAGE_ALLOCATION_TYPE, PAGE_PROTECT, PAGE_TYPE
import common

EINVAL = 22
_TRUNCATE = 0xFFFFFFFF

TIME_BASE = 1576292568
RAND_BASE = 0
TICK_BASE = 86400000  # 1 day in millisecs

class Msvcrt(ApiHandler):
    """
    Implements functions from various versions of the C runtime on Windows
    """
    name = 'msvcrt'
    api_call = ApiHandler.api_call

    def __init__(self, emu):

        super(Msvcrt, self).__init__(emu)

        self.stdin = 0
        self.stdout = 1
        self.stderr = 2

        self.rand_int = RAND_BASE

        self.funcs = {}
        self.data = {}
        self.wintypes = windef

        self.tick_counter = TICK_BASE

        super().__get_api_attrs__(self) # initalize info about each apis


    # Reference: https://wiki.osdev.org/Visual_C%2B%2B_Runtime
    @api_call('_initterm_e', argc=2, conv=cv.CALL_CONV_CDECL)
    def _initterm_e(self, emu, argv, ctx={}):
        """
        static int _initterm_e(_PIFV * pfbegin,
                                    _PIFV * pfend)
        """

        pfbegin, pfend = argv

        rv = 0

        return rv

    @api_call('__p___argv', argc=0, conv=cv.CALL_CONV_CDECL)
    def __p___argv(self, emu, argv, ctx={}):
        """char *** __p___argv ()"""

        ptr_size = emu.ptr_size
        _argv = emu.get_argv()

        argv = [(a + '\x00\x00\x00\x00').encode('utf-8') for a in _argv]

        array_size = (ptr_size * (len(argv) + 1))
        total = sum([len(a) for a in argv])
        total += array_size

        sptr = 0
        pptr = 0

        pArgs = emu.default_heap_alloc(total+ptr_size).address
        pptr = pArgs + ptr_size
        common.mem_write(emu.emu_eng, pArgs, pptr.to_bytes(ptr_size, 'little'))
        sptr = pptr + array_size

        for a in argv:
            common.mem_write(emu.emu_eng, pptr, sptr.to_bytes(ptr_size, 'little'))
            pptr += ptr_size
            common.mem_write(emu.emu_eng, sptr, a)
            sptr += len(a)

        common.mem_write(emu.emu_eng, pptr, b'\x00' * ptr_size)
        rv = pArgs

        return rv

    @api_call('__p___argc', argc=0, conv=cv.CALL_CONV_CDECL)
    def __p___argc(self, emu, argv, ctx={}):
        """int * __p___argc ()"""

        _argv = emu.get_argv()
        
        pMem = emu.default_heap_alloc(self.ptr_size*2).address
        common.mem_write(emu.emu_eng, pMem, len(_argv).to_bytes(4, 'little'))
        
        return pMem
    
    @api_call('_get_initial_narrow_environment', argc=0, conv=cv.CALL_CONV_CDECL)
    def _get_initial_narrow_environment(self, emu, argv, ctx={}):
        """char** _get_initial_narrow_environment ()"""

        ptr_size = self.get_ptr_size()
        env = common.get_env(emu)
        total = ptr_size
        sptr = total
        pptr = 0
        fmt_env = []
        for k, v in env.items():
            envstr = '%s=%s\x00' % (k, v)
            envstr = envstr.encode('utf-8')
            total += len(envstr)
            fmt_env.append(envstr)
            total += ptr_size
            sptr += ptr_size

        pMem = emu.default_heap_alloc(self.ptr_size*2).address

        pptr = pMem
        sptr += pMem

        for v in fmt_env:
            self.mem_write(pptr, sptr.to_bytes(ptr_size, 'little'))
            pptr += ptr_size
            self.mem_write(sptr, v)
            sptr += len(v)

        return pMem
    



    
    
