import math
import struct

import speakeasy.winenv.defs.windows.windows as windef
from unicorn.unicorn_const import UC_ARCH_X86
from cb_handler import CALL_CONV as cv
from cb_handler import ApiHandler
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

        super().__set_api_attrs__(self) # initalize info about each apis


    # Reference: https://wiki.osdev.org/Visual_C%2B%2B_Runtime
    @api_call('_initterm', argc=2, conv=cv.CALL_CONV_CDECL)
    def _initterm(self, emu, argv, ctx={}):
        """
        static int _initterm_e(_PIFV * pfbegin,
                                    _PIFV * pfend)
        """

        pfbegin, pfend = argv

        rv = 0

        return rv

    @api_call('_initterm_e', argc=2, conv=cv.CALL_CONV_CDECL)
    def _initterm_e(self, emu, argv, ctx={}):
        """
        static int _initterm_e(_PIFV * pfbegin,
                                    _PIFV * pfend)
        """

        return self._initterm(emu, argv, ctx={})

    @api_call('__p___argv', argc=0, conv=cv.CALL_CONV_CDECL)
    def __p___argv(self, emu, argv, ctx={}):
        """char *** __p___argv ()"""

        ptr_size = emu.ptr_size
        _argv = emu.get_param()

        argv = [(a + '\x00\x00\x00\x00').encode('utf-8') for a in _argv]

        array_size = (ptr_size * (len(argv) + 1))
        total = sum([len(a) for a in argv])
        total += array_size

        sptr = 0
        pptr = 0

        pArgs = emu.default_heap_alloc(total+ptr_size)
        pptr = pArgs + ptr_size
        common.mem_write(emu.uc_eng, pArgs, pptr.to_bytes(ptr_size, 'little'))
        sptr = pptr + array_size

        for a in argv:
            common.mem_write(emu.uc_eng, pptr, sptr.to_bytes(ptr_size, 'little'))
            pptr += ptr_size
            common.mem_write(emu.uc_eng, sptr, a)
            sptr += len(a)

        common.mem_write(emu.uc_eng, pptr, b'\x00' * ptr_size)
        rv = pArgs

        return rv

    @api_call('__p___argc', argc=0, conv=cv.CALL_CONV_CDECL)
    def __p___argc(self, emu, argv, ctx={}):
        """int * __p___argc ()"""

        _argv = emu.get_param()
        
        pMem = emu.default_heap_alloc(self.ptr_size*2)
        common.mem_write(emu.uc_eng, pMem, len(_argv).to_bytes(4, 'little'))
        
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

        pMem = emu.default_heap_alloc(self.ptr_size*2)

        pptr = pMem
        sptr += pMem

        for v in fmt_env:
            common.mem_write(emu.uc_eng ,pptr, sptr.to_bytes(ptr_size, 'little'))
            pptr += ptr_size
            common.mem_write(emu.uc_eng ,sptr, v)
            sptr += len(v)

        return pMem

    @api_call('exit', argc=1, conv=cv.CALL_CONV_CDECL)
    def exit(self, emu, argv, ctx={}):
        """
        void exit(
           int const status
        );
        """
        emu.quit_emu_sig()
        return 0

    @api_call('_exit', argc=1, conv=cv.CALL_CONV_CDECL)
    def _exit(self, emu, argv, ctx={}):
        """
        void _exit(
           int const status
        );
        """
        emu.quit_emu_sig()
        return 0
    
    @api_call('_CrtSetCheckCount', argc=1, conv=cv.CALL_CONV_CDECL)
    def _crtsetcheckcount(self, emu, argv, ctx={}):
        """int _CrtSetCheckCount( int chk_count );"""
        rv = 0
        return rv

    @api_call('__acrt_iob_func', argc=1, conv=cv.CALL_CONV_CDECL)
    def __acrt_iob_func(self, emu, argv, ctx={}):
        """FILE * __acrt_iob_func (fd)"""

        fd, = argv

        return fd

    @api_call('printf', argc=0, conv=cv.CALL_CONV_CDECL)
    def printf(self, emu, argv, ctx={}):

        arch = emu.get_arch()
        if arch == UC_ARCH_X86:
            fmt, va_list = ApiHandler.get_argv(emu, cv.CALL_CONV_CDECL, 2)[:2]
        else:
            raise Exception ("Unsupported architecture")

        rv = 0

        fmt_str = common.read_mem_string(emu.uc_eng, fmt, 1)
        fmt_cnt = self.get_va_arg_count(fmt_str)

        vargs = self.va_args2(fmt_cnt)
        fin = common.make_fmt_str(emu, fmt_str, vargs)

        rv = len(fin)
        argv.append(fin)

        print(fin)

        return rv

    @api_call('__stdio_common_vfprintf', argc=0, conv=cv.CALL_CONV_CDECL)
    def __stdio_common_vfprintf(self, emu, argv, ctx={}):

        
        arch = emu.get_arch()
        if arch == UC_ARCH_X86:
            opts, opts2, stream, fmt, _, va_list = ApiHandler.get_argv(emu, cv.CALL_CONV_CDECL, 6)[:6]
        else:
            raise Exception ("Unsupported architecture")

        rv = 0

        fmt_str = common.read_mem_string(emu.uc_eng, fmt, 1)
        fmt_cnt = self.get_va_arg_count(fmt_str)

        vargs = self.va_args(va_list, fmt_cnt)
        fin = common.make_fmt_str(emu, fmt_str, vargs)

        argv[:] = [opts, stream, fin]

        rv = len(fin)

        return rv

    @api_call('puts', argc=1, conv=cv.CALL_CONV_CDECL)
    def puts(self, emu, argv, ctx={}):
        """
        int puts(
           const char *str
        );
        """
        s, = argv

        string = common.read_mem_string(emu.uc_eng, s, 1)
        argv[0] = string
        rv = len(string)

        return rv

    @api_call('_putws', argc=1, conv=cv.CALL_CONV_CDECL)
    def _putws(self, emu, argv, ctx={}):
        """
        int _putws(
           const wchar_t *str
        );
        """
        s, = argv

        string = common.read_wide_string(emu.uc_eng, s, 20)
        argv[0] = string
        rv = len(string)

        # print(string)

        return rv

    @api_call('strlen', argc=1, conv=cv.CALL_CONV_CDECL)
    def strlen(self, emu, argv, ctx={}):
        """
        size_t strlen(
            const char *str
        );
        """
        s, = argv

        string = common.read_mem_string(emu.uc_eng, s, 1)
        argv[0] = string
        rv = len(string)

        return rv

    @api_call('strcpy', argc=2, conv=cv.CALL_CONV_CDECL)
    def strcpy(self, emu, argv, ctx={}):
        """
        char *strcpy(
           char *strDestination,
           const char *strSource
        );
        """
        dest, src = argv
        s = common.read_string(emu.uc_eng, src)

        common.write_string(emu.uc_eng, s, dest)
        argv[1] = s
        return dest

    @api_call('wcscpy', argc=2, conv=cv.CALL_CONV_CDECL)
    def wcscpy(self, emu, argv, ctx={}):
        """
        wchar_t *wcscpy(
            wchar_t *strDestination,
            const wchar_t *strSource
        );
        """
        dest, src = argv
        ws = common.read_wide_string(emu.uc_eng, src)
        common.write_wide_string(emu.uc_eng, ws, dest)
        argv[1] = ws
        return dest

    @api_call('strncpy', argc=3, conv=cv.CALL_CONV_CDECL)
    def strncpy(self, emu, argv, ctx={}):
        """
        char * strncpy(
            char * destination,
            const char * source,
            size_t num
        );
        """
        dest, src, length = argv
        s = common.read_string(emu.uc_eng, src, max_chars=length)
        if len(s) < length:
            s += '\x00'*(length-len(s))
        common.write_string(emu.uc_eng, s, dest)
        argv[1] = s
        return dest

    @api_call('memcpy', argc=3, conv=cv.CALL_CONV_CDECL)
    def memcpy(self, emu, argv, ctx={}):
        """
        void *memcpy(
            void *dest,
            const void *src,
            size_t count
            );
        """
        dest, src, count = argv
        data = emu.uc_eng.mem_read(src, count)
        if isinstance(data, bytearray):
            data = bytes(data)
        emu.uc_eng.mem_write(dest, data)

        return dest

    @api_call('memmove', argc=3, conv=cv.CALL_CONV_CDECL)
    def memmove(self, emu, argv, ctx={}):
        """
        void *memmove(
            void *dest,
            const void *src,
            size_t count
        );
        """

        return self.memcpy(emu, argv, ctx)

    @api_call('memset', argc=3, conv=cv.CALL_CONV_CDECL)
    def memset(self, emu, argv, ctx={}):
        """
        void *memset ( void * ptr,
                       int value,
                       size_t num );
        """

        ptr, value, num = argv

        data = value.to_bytes(1, 'little') * num
        emu.uc_eng.mem_write(ptr, data)

        return ptr

    @api_call('memcmp', argc=3, conv=cv.CALL_CONV_CDECL)
    def memcmp(self, emu, argv, ctx={}):
        """
        int memcmp(
           const void *buffer1,
           const void *buffer2,
           size_t count
        );
        """
        diff = 0
        buff1, buff2, cnt = argv
        for i in range(cnt):
            b1 = emu.uc_eng.mem_read(buff1, 1)
            b2 = emu.uc_eng.mem_read(buff2, 1)
            if b1 > b2:
                diff = 1
                break
            elif b1 < b2:
                diff = -1
                break

        return diff