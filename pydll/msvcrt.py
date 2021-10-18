import math
import struct

import speakeasy.winenv.defs.windows.windows as windef
from unicorn.unicorn_const import UC_ARCH_X86, UC_ERR_EXCEPTION
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

    def __init__(self, win_emu):
        self.win_emu = win_emu
        self.stdin = 0
        self.stdout = 1
        self.stderr = 2

        self.rand_int = RAND_BASE

        self.funcs = {}
        self.data = {}
        self.wintypes = windef
        self.ptr_size = self.win_emu.get_ptr_size()
        self.tick_counter = TICK_BASE

        super().__set_api_attrs__(self) # initalize info about each apis


    # Reference: https://wiki.osdev.org/Visual_C%2B%2B_Runtime
    @api_call('_initterm', argc=2, conv=cv.CALL_CONV_CDECL)
    def _initterm(self, proc, argv, ctx={}):
        """
        static int _initterm_e(_PIFV * pfbegin,
                                    _PIFV * pfend)
        """

        pfbegin, pfend = argv

        rv = 0

        return rv

    @api_call('_initterm_e', argc=2, conv=cv.CALL_CONV_CDECL)
    def _initterm_e(self, proc, argv, ctx={}):
        """
        static int _initterm_e(_PIFV * pfbegin,
                                    _PIFV * pfend)
        """

        return self._initterm(proc, argv, ctx={})

    @api_call('__p___argv', argc=0, conv=cv.CALL_CONV_CDECL)
    def __p___argv(self, proc, argv, ctx={}):
        """char *** __p___argv ()"""

        ptr_size = proc.ptr_size
        _argv = proc.get_param()
        if not _argv:
            return 0
        argv = [(a + '\x00\x00\x00\x00').encode('utf-8') for a in _argv]

        array_size = (ptr_size * (len(argv) + 1))
        total = sum([len(a) for a in argv])
        total += array_size

        sptr = 0
        pptr = 0

        #pArgs = proc.default_heap_alloc(total+ptr_size)
        pArgs = self.win_emu.mem_manager.alloc_heap(proc.default_proc_heap, total+ptr_size)
        pptr = pArgs + ptr_size
        common.mem_write(proc.uc_eng, pArgs, pptr.to_bytes(ptr_size, 'little'))
        sptr = pptr + array_size

        for a in argv:
            proc.write_mem_self(pptr, sptr.to_bytes(ptr_size, 'little'))
            pptr += ptr_size
            proc.write_mem_self(sptr, a)
            sptr += len(a)

        proc.write_mem_self(pptr, pptr, b'\x00' * ptr_size)
        
        rv = pArgs

        return rv

    @api_call('__p___argc', argc=0, conv=cv.CALL_CONV_CDECL)
    def __p___argc(self, proc, argv, ctx={}):
        """int * __p___argc ()"""

        _argv = proc.get_param()
        if not _argv:
            return 0
        pMem = self.win_emu.mem_manager.alloc_heap(proc.default_proc_heap, self.ptr_size*2)
        proc.write_mem_self(pMem, len(_argv).to_bytes(4, 'little'))
        
        return pMem
    
    @api_call('_get_initial_narrow_environment', argc=0, conv=cv.CALL_CONV_CDECL)
    def _get_initial_narrow_environment(self, proc, argv, ctx={}):
        """char** _get_initial_narrow_environment ()"""

        ptr_size = self.win_emu.get_ptr_size()
        env = common.get_env(self.win_emu)
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

        pMem = self.win_emu.mem_manager.alloc_heap(proc.proc_default_heap, ptr_size*2)
        pptr = pMem
        sptr += pMem

        for v in fmt_env:
            proc.write_mem_self(pptr, sptr.to_bytes(ptr_size, 'little'))
            pptr += ptr_size
            proc.write_mem_self(sptr, v)
            sptr += len(v)

        return pMem

    @api_call('exit', argc=1, conv=cv.CALL_CONV_CDECL)
    def exit(self, proc, argv, ctx={}):
        """
        void exit(
           int const status
        );
        """
        proc.exit()
        return 0
    
    @api_call('_exit', argc=1, conv=cv.CALL_CONV_CDECL)
    def _exit(self, proc, argv, ctx={}):
        """
        void _exit(
           int const status
        );
        """
        self.exit(proc, argv, ctx)
        return 0
    
    @api_call('_cexit', argc=1, conv=cv.CALL_CONV_CDECL)
    def _cexit(self, proc, argv, ctx={}):
        """
        void _cexit(
           int const status
        );
        """
        self.exit(proc, argv, ctx)

        return 0
    
    @api_call('_CrtSetCheckCount', argc=1, conv=cv.CALL_CONV_CDECL)
    def _crtsetcheckcount(self, proc, argv, ctx={}):
        """int _CrtSetCheckCount( int chk_count );"""
        rv = 0
        return rv

    @api_call('__acrt_iob_func', argc=1, conv=cv.CALL_CONV_CDECL)
    def __acrt_iob_func(self, proc, argv, ctx={}):
        """FILE * __acrt_iob_func (fd)"""

        fd, = argv

        return fd

    @api_call('printf', argc=0, conv=cv.CALL_CONV_CDECL)
    def printf(self, proc, argv, ctx={}):

        arch = proc.get_arch()
        if arch == UC_ARCH_X86:
            fmt, va_list = ApiHandler.get_argv(proc, cv.CALL_CONV_CDECL, 2)[:2]
        else:
            raise Exception ("Unsupported architecture")

        rv = 0

        fmt_str = common.read_mem_string(proc.uc_eng, fmt, 1)
        fmt_cnt = self.get_va_arg_count(fmt_str)

        vargs = self.va_args2(proc, fmt_cnt)
        fin = common.make_fmt_str(proc, fmt_str, vargs)

        rv = len(fin)
        argv.append(fin)

        # print(fin)

        return rv

    @api_call('wprintf', argc=0, conv=cv.CALL_CONV_CDECL)
    def wprintf(self, proc, argv, ctx={}):

        arch = proc.get_arch()
        if arch == UC_ARCH_X86:
            fmt, va_list = ApiHandler.get_argv(proc, cv.CALL_CONV_CDECL, 2)[:2]
        else:
            raise Exception ("Unsupported architecture")

        rv = 0

        fmt_str = common.read_wide_string(proc.uc_eng, fmt)
        fmt_cnt = self.get_va_arg_count(fmt_str)

        vargs = self.va_args2(proc, fmt_cnt)
        fin = common.make_fmt_str(proc, fmt_str, vargs, True)

        rv = len(fin)
        argv.append(fin)

        # print(fin)

        return rv

    @api_call('__stdio_common_vfprintf', argc=0, conv=cv.CALL_CONV_CDECL)
    def __stdio_common_vfprintf(self, proc, argv, ctx={}):
        arch = proc.get_arch()
        if arch == UC_ARCH_X86:
            opts, opts2, stream, fmt, _, va_list = ApiHandler.get_argv(proc, cv.CALL_CONV_CDECL, 6)[:6]
        else:
            raise Exception ("Unsupported architecture")

        fmt_str = proc.read_string(fmt, 1)
        fmt_cnt = self.get_va_arg_count(fmt_str)
        vargs = self.va_args(proc, va_list, fmt_cnt)
        fin = common.make_fmt_str(proc, fmt_str, vargs)
        argv[:] = [opts, stream, fin]

        rv = len(fin)

        return rv

    @api_call('puts', argc=1, conv=cv.CALL_CONV_CDECL)
    def puts(self, proc, argv, ctx={}):
        """
        int puts(
           const char *str
        );
        """
        s, = argv
        string = proc.read_string(s, 1)
        argv[0] = string
        rv = len(string)

        return rv

    @api_call('_putws', argc=1, conv=cv.CALL_CONV_CDECL)
    def _putws(self, proc, argv, ctx={}):
        """
        int _putws(
           const wchar_t *str
        );
        """
        s, = argv
        string = common.read_string(s, 2, 20)
        argv[0] = string
        rv = len(string)

        # print(string)

        return rv

    @api_call('strlen', argc=1, conv=cv.CALL_CONV_CDECL)
    def strlen(self, proc, argv, ctx={}):
        """
        size_t strlen(
            const char *str
        );
        """
        s, = argv
        string = proc.read_string(s, 1)
        argv[0] = string
        rv = len(string)

        return rv

    @api_call('strcpy', argc=2, conv=cv.CALL_CONV_CDECL)
    def strcpy(self, proc, argv, ctx={}):
        """
        char *strcpy(
           char *strDestination,
           const char *strSource
        );
        """
        dest, src = argv
        s = proc.read_string(src, 1)
        bytz = s.encode("ascii")
        proc.write_mem_self(bytz, len(bytz))
        argv[1] = s
        return dest

    @api_call('wcscpy', argc=2, conv=cv.CALL_CONV_CDECL)
    def wcscpy(self, proc, argv, ctx={}):
        """
        wchar_t *wcscpy(
            wchar_t *strDestination,
            const wchar_t *strSource
        );
        """
        dest, src = argv
        ws = common.read_wide_string(proc.uc_eng, src)
        common.write_wide_string(proc.uc_eng, ws, dest)
        argv[1] = ws
        return dest

    @api_call('wcslen', argc=1, conv=cv.CALL_CONV_CDECL)
    def wcslen(self, proc, argv, ctx={}):
        """
        size_t wcslen(
          const wchar_t* wcs
        );
        """
        s, = argv
        string = proc.read_string(s, 2)
        argv[0] = string
        rv = len(string)

        return rv

    @api_call('wcscat', argc=2, conv=cv.CALL_CONV_CDECL)
    def wcscat(self, proc, argv, ctx={}):
        '''
        wchar_t *wcscat(
           wchar_t *strDestination,
           const wchar_t *strSource
        );
        '''
        _str1, _str2 = argv
        s1 = proc.read_string(_str1, 2)
        s2 = proc.read_string(_str2, 2)
        
        argv[0] = s1
        argv[1] = s2
        new = (s1 + s2).encode('utf-16le')
        proc.write_mem_self(_str1, new + b'\x00\x00')
        
        return _str1

    @api_call('_wtoi', argc=1, conv=cv.CALL_CONV_CDECL)
    def _wtoi(self, proc, argv, ctx={}):
        pStr, = argv
        _str = proc.read_string(pStr, 2)

        return int.from_bytes(_str.encode("utf-16le"), "little")

    @api_call('strncpy', argc=3, conv=cv.CALL_CONV_CDECL)
    def strncpy(self, proc, argv, ctx={}):
        """
        char * strncpy(
            char * destination,
            const char * source,
            size_t num
        );
        """
        dest, src, length = argv
        s = proc.read_string(src, 1, max_len=length)
        if len(s) < length:
            s += '\x00'*(length-len(s))
        proc.write_mem_self(s, dest)
        
        argv[1] = s
        return dest

    @api_call('memcpy', argc=3, conv=cv.CALL_CONV_CDECL)
    def memcpy(self, proc, argv, ctx={}):
        """
        void *memcpy(
            void *dest,
            const void *src,
            size_t count
            );
        """
        dest, src, count = argv
        data = proc.read_mem_self(src, count)
        if isinstance(data, bytearray):
            data = bytes(data)
        proc.write_mem_self(dest, data)

        return dest

    @api_call('memmove', argc=3, conv=cv.CALL_CONV_CDECL)
    def memmove(self, proc, argv, ctx={}):
        """
        void *memmove(
            void *dest,
            const void *src,
            size_t count
        );
        """

        return self.memcpy(proc, argv, ctx)

    @api_call('memset', argc=3, conv=cv.CALL_CONV_CDECL)
    def memset(self, proc, argv, ctx={}):
        """
        void *memset ( void * ptr,
                       int value,
                       size_t num );
        """

        ptr, value, num = argv

        data = value.to_bytes(1, 'little') * num
        proc.write_mem_self(ptr, data)

        return ptr

    @api_call('memcmp', argc=3, conv=cv.CALL_CONV_CDECL)
    def memcmp(self, proc, argv, ctx={}):
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
            b1 = proc.read_mem_self(buff1, 1)
            b2 = proc.read_mem_self(buff2, 1)
            
            if b1 > b2:
                diff = 1
                break
            elif b1 < b2:
                diff = -1
                break

        return diff

    @api_call('malloc', argc=1, conv=cv.CALL_CONV_CDECL)
    def malloc(self, proc, argv, ctx={}):
        """
        void *malloc(
        size_t size
        );
        """
        size, = argv
        pMem = self.win_emu.mem_manager.alloc_heap(proc.proc_default_heap, size)
        
        return pMem

    @api_call('calloc', argc=2, conv=cv.CALL_CONV_CDECL)
    def calloc(self, proc, argv, ctx={}):
        """
        void *calloc(
        size_t num,
        size_t size
        );
        """
        num, size, = argv
        pMem = self.malloc(proc, num*size, ctx)
        self.memset(proc, (pMem, 0, num*size))
        return 

    @api_call('free', argc=1, conv=cv.CALL_CONV_CDECL)
    def free(self, proc, argv, ctx={}):
        """
        void free(
        void *memblock
        );
        """
        mem, = argv
        self.win_emu.mem_manager.free_heap(proc.proc_default_heap.handle, mem)