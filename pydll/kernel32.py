# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# orca-eaa5a Edit
import os

from unicorn.x86_const import UC_X86_REG_ESP
from speakeasy_origin.windef.windows.windows import MEM_PRIVATE

from unicorn.unicorn_const import UC_HOOK_CODE
from speakeasy_origin import windef
import pydll

import speakeasy.winenv.defs.windows.windows as windefs
import speakeasy.winenv.defs.windows.kernel32 
from cb_handler import ApiHandler
from cb_handler import CALL_CONV as cv
import common
import speakeasy.winenv.defs.windows.kernel32 as k32types
import pymanager.defs.mem_defs as memdef
from cb_handler import Dispatcher
from cb_handler import CodeCBHandler as code_cb_handler

class Kernel32(ApiHandler):
    name = "kernel32"
    api_call = ApiHandler.api_call

    def __init__(self, emu):
        self.emu = emu
        self.funcs = {}

        self.find_files = {}
        self.find_volumes = {}
        self.find_files = {}
        self.find_volumes = {}
        self.snapshots = {}
        self.find_resources = {}
        self.tick_counter = 86400000  # 1 day in millisecs
        self.perf_counter = 0x5fd27d571f
        self.command_lines = [None] * 3
        self.startup_info = {}

        self.k32types = k32types

        super().__set_api_attrs__(self) # initalize info about each apis

    def normalize_res_identifier(self, emu, cw, val):
        mask = (16 ** (emu.get_ptr_size() // 2) - 1) << 16
        if val & mask:  # not an INTRESOURCE
            name = emu.read_mem_string(val, cw)
            if name[0] == "#":
                try:
                    name = int(name[1:])
                except Exception:
                    return 0
        else:
            name = val

        return name

    def find_resource(self, pe, name, type_):
        # find type
        resource_type = None

        if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            return None

        for restype in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if type(type_) is str and restype.name is not None:
                if type_ == restype.name.decode('utf8'):
                    resource_type = restype
                    break
            elif type(type_) is int and hasattr(restype.struct, 'Id'):
                if type_ == restype.struct.Id:
                    resource_type = restype
                    break

        if not resource_type:
            return None

        if not hasattr(resource_type, 'directory'):
            return None

        for resource_id in resource_type.directory.entries:
            if type(name) is str and resource_id.name is not None:
                if name == resource_id.name.decode('utf8'):
                    return resource_id.directory.entries[0]
            elif type(name) is int and hasattr(resource_id.struct, 'Id'):
                if name == resource_id.struct.Id:
                    return resource_id.directory.entries[0]

        return None

    @api_call('GetThreadLocale', argc=0)
    def GetThreadLocale(self, emu, argv, ctx={}):
        '''
        LCID GetThreadLocale();
        '''
        return 0xC000

    @api_call('CreateThread', argc=6)
    def CreateThread(self, emu, argv, ctx={}):
        '''
        HANDLE CreateThread(
            LPSECURITY_ATTRIBUTES   lpThreadAttributes,
            SIZE_T                  dwStackSize,
            LPTHREAD_START_ROUTINE  lpStartAddress,
            __drv_aliasesMem LPVOID lpParameter,
            DWORD                   dwCreationFlags,
            LPDWORD                 lpThreadId
        );
        '''

        (
            lpThreadAttributes, 
            dwStackSize, 
            lpStartAddress,
            lpParameter,
            dwCreationFlags, 
            lpThreadId
        ) = argv

        # without get parameter

        stack_size = dwStackSize
        if stack_size == 0:
            stack_size = 1024 * 1024 # 1MB Stack Default
        tHandle = emu.create_thread(lpStartAddress, stack_size, lpParameter, dwCreationFlags,)
        t_obj = emu.obj_manager.get_obj_by_handle(tHandle)

        if lpThreadId:
            emu.uc_eng.mem_write(lpThreadId, t_obj.get_id().to_bytes(4, 'little'))

        if not (dwCreationFlags & windefs.CREATE_SUSPENDED):
            self.ResumeThread(emu, (tHandle), ctx)

        return tHandle

    @api_call('ResumeThread', argc=1)
    def ResumeThread(self, emu, argv, ctx={}):
        '''
        DWORD ResumeThread(
            HANDLE hThread
        );
        '''
        hThread, = argv
        idx = 0
        for thread_handle, t_obj in emu.threads:
            if thread_handle == hThread:
                break
            idx+=1
        hThread, t_obj = emu.threads.pop(idx)

        import unicorn.x86_const as u_x86
        import struct

        sp = emu.uc_eng.reg_read(u_x86.UC_X86_REG_ESP)
        rv = struct.unpack("<I", emu.uc_eng.mem_read(sp, emu.ptr_size))[0]

        if t_obj.suspend_count > 0:
            t_obj.suspend_count-=1
        if t_obj.suspend_count == 0:
            emu.switch_thread_context(t_obj, rv)

        return t_obj.suspend_count

    @api_call('WaitForSingleObject', argc=2)
    def WaitForSingleObject(self, emu, argv, ctx={}):
        '''
        DWORD WaitForSingleObject(
        HANDLE hHandle,
        DWORD  dwMilliseconds
        );
        '''
        hHandle, dwMilliseconds = argv

        # TODO
        if dwMilliseconds == 1:
            rv = windefs.WAIT_TIMEOUT
        else:
            rv = windefs.WAIT_OBJECT_0

        return rv

    @api_call('OutputDebugString', argc=1)
    def OutputDebugString(self, emu, argv, ctx={}):
        '''
        void OutputDebugStringA(
            LPCSTR lpOutputString
        );
        '''
        _str, = argv
        cw = common.get_char_width(ctx)
        argv[0] = common.read_mem_string(emu.uc_eng, _str, cw)

    @api_call('lstrlen', argc=1)
    def lstrlen(self, emu, argv, ctx={}):
        '''
        int lstrlen(
            LPCSTR lpString
        );
        '''
        src, = argv
        try:
            cw = common.get_char_width(ctx)
        except Exception:
            cw = 1
        s = common.read_mem_string(emu.uc_eng, src, cw)

        argv[0] = s

        return len(s)

    @api_call('strlen', argc=1)
    def strlen(self, emu, argv, ctx={}):
        '''
        int strlen(
            LPCSTR lpString
        );
        '''
        return self.strlen(emu, argv, ctx)

    @api_call('GetThreadTimes', argc=5)
    def GetThreadTimes(self, emu, argv, ctx={}):
        '''
        BOOL GetThreadTimes(
            HANDLE     hThread,
            LPFILETIME lpCreationTime,
            LPFILETIME lpExitTime,
            LPFILETIME lpKernelTime,
            LPFILETIME lpUserTime
        );
        '''
        hnd, lpCreationTime, lpExitTime, lpKernelTime, lpUserTime = argv

        if lpCreationTime:
            common.mem_write(emu.uc_eng, lpCreationTime, b'\x20\x20\x00\x00')
        return True

    @api_call('GetProcessHeap', argc=0)
    def GetProcessHeap(self, emu, argv, ctx={}):
        '''
        HANDLE GetProcessHeap();
        '''
        return emu.proc_default_heap.address

    @api_call('GetProcessVersion', argc=1)
    def GetProcessVersion(self, emu, argv, ctx={}):
        '''
        DWORD GetProcessVersion(
            DWORD ProcessId
        );
        '''

        ver = emu.emu_os_v
        major = ver['major']
        minor = ver['minor']

        rv = 0xFFFFFFFF & (major << 16 | minor)

        return rv

    @api_call('DisableThreadLibraryCalls', argc=1)
    def DisableThreadLibraryCalls(self, emu, argv, ctx={}):
        '''
        BOOL DisableThreadLibraryCalls(
            HMODULE hLibModule
        );
        '''

        hLibModule, = argv

        return True

    @api_call('LoadLibrary', argc=1)
    def LoadLibrary(self, emu, argv, ctx={}):
        '''HMODULE LoadLibrary(
            LPTSTR lpLibFileName
        );'''

        lib_name, = argv
        hmod = windefs.NULL

        cw = common.get_char_width(ctx)
        req_lib = common.read_mem_string(emu.uc_eng, lib_name, cw)
        lib = ApiHandler.api_set_schema(req_lib)

        hmod = emu.load_library(lib)
        argv[0] = req_lib

        return hmod

    @api_call('LoadLibraryEx', argc=3)
    def LoadLibraryEx(self, emu, argv, ctx={}):
        '''HMODULE LoadLibraryExA(
            LPCSTR lpLibFileName,
            HANDLE hFile,
            DWORD  dwFlags
        );'''

        lib_name, _, dwFlags = argv

        hmod = 0

        cw = common.get_char_width(ctx)
        req_lib = common.read_mem_string(emu.uc_eng, lib_name, cw)
        lib = ApiHandler.api_set_schema(req_lib)

        hmod = emu.load_library(lib)

        flags = {
            0x1: 'DONT_RESOLVE_DLL_REFERENCES',
            0x10: 'LOAD_IGNORE_CODE_AUTHZ_LEVEL',
            0x2: 'LOAD_LIBRARY_AS_DATAFILE',
            0x40: 'LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE',
            0x20: 'LOAD_LIBRARY_AS_IMAGE_RESOURCE',
            0x200: 'LOAD_LIBRARY_SEARCH_APPLICATION_DIR',
            0x1000: 'LOAD_LIBRARY_SEARCH_DEFAULT_DIRS',
            0x100: 'LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR',
            0x800: 'LOAD_LIBRARY_SEARCH_SYSTEM32',
            0x400: 'LOAD_LIBRARY_SEARCH_USER_DIRS',
            0x8: 'LOAD_WITH_ALTERED_SEARCH_PATH',
        }

        pretty_flags = ' | '.join([name for bit, name in flags.items() if dwFlags & bit])

        argv[0] = req_lib
        argv[1] = argv[1]
        argv[2] = pretty_flags

        if not hmod:
            emu.set_last_error(windefs.ERROR_MOD_NOT_FOUND)

        return hmod

    @api_call('GetModuleHandleEx', argc=3)
    def GetModuleHandleEx(self, emu, argv, ctx={}):
        '''
        BOOL GetModuleHandleExA(
            DWORD   dwFlags,
            LPCSTR  lpModuleName,
            HMODULE *phModule
        );
        '''
        dwFlags, lpModuleName, phModule = argv

        hmod = self.GetModuleHandle(emu, [lpModuleName], ctx)
        if phModule:
            _mod = (hmod).to_bytes(emu.get_ptr_size(), 'little')
            emu.uc_eng.mem_write(phModule, _mod)
        return hmod

    @api_call('GetModuleHandle', argc=1)
    def GetModuleHandle(self, emu, argv, ctx={}):
        '''HMODULE GetModuleHandle(
          LPCSTR lpModuleName
        );'''

        mod_name, = argv

        cw = self.get_char_width(ctx)
        rv = 0

        if not mod_name:
            rv = emu.image_base
        else:
            lib = common.read_mem_string(emu.uc_eng, mod_name, cw)
            if lib not in emu.imp:
                lib = ApiHandler.api_set_schema(lib)
            if lib in emu.imp:
                rv = pydll.SYSTEM_DLL_BASE[lib]
            else:
                rv = 0
                
        return rv

    @api_call('GetTickCount', argc=0)
    def GetTickCount(self, emu, argv, ctx={}):
        '''
        DWORD GetTickCount();
        '''

        self.tick_counter += 20

        return self.tick_counter

    @api_call('GetTickCount64', argc=0)
    def GetTickCount64(self, emu, argv, ctx={}):
        '''
        DWORD GetTickCount();
        '''
        self.GetTickCount(emu, argv, ctx)

        return self.tick_counter

    @api_call('CreateFile', argc=7)
    def CreateFile(self, emu, argv, ctx={}):
        '''
        HANDLE CreateFile(
          LPTSTR                lpFileName,
          DWORD                 dwDesiredAccess,
          DWORD                 dwShareMode,
          LPSECURITY_ATTRIBUTES lpSecurityAttributes,
          DWORD                 dwCreationDisposition,
          DWORD                 dwFlagsAndAttributes,
          HANDLE                hTemplateFile
        );
        '''
        pFileName, access, share, secAttr, disp, flags, template = argv
        
        cw = common.get_char_width(ctx)
        f_name = common.read_mem_string(emu.uc_eng, pFileName, cw)
        py_io_mode = emu.fs_manager.convert_io_mode(f_name, access, disp)

        py_file_handle = emu.fs_manager.create_file(f_name, py_io_mode)

        return py_file_handle.handle_id

    @api_call('WriteFile', argc=5)
    def WriteFile(self, emu, argv, ctx={}):
        """
         BOOL WriteFile(
          HANDLE       hFile,
          LPCVOID      lpBuffer,
          DWORD        nNumberOfBytesToWrite,
          LPDWORD      lpNumberOfBytesWritten,
          LPOVERLAPPED lpOverlapped
        );
        """
        hFile, lpBuffer, num_bytes, pBytesWritten, lpOverlapped = argv
        rv = 0
        
        data = emu.uc_eng.mem_read(lpBuffer, num_bytes)
        rv = emu.fs_manager.write_file(hFile, data)
        emu.uc_eng.mem_write(pBytesWritten, rv.to_bytes(emu.ptr_size, byteorder="little"))

        return rv

    @api_call('ReadFile', argc=5)
    def ReadFile(self, emu, argv, ctx={}):
        '''
        BOOL ReadFile(
          HANDLE       hFile,
          LPVOID       lpBuffer,
          DWORD        nNumberOfBytesToRead,
          LPDWORD      lpNumberOfBytesRead,
          LPOVERLAPPED lpOverlapped
        );
        '''
        hFile, lpBuffer, num_bytes, lpBytesRead, lpOverlapped = argv

        rb = emu.fs_manager.read_file(hFile, num_bytes)
        emu.uc_eng.mem_write(lpBuffer, rb)
        emu.uc_eng.mem_write(lpBytesRead, len(rb).to_bytes(emu.ptr_size, byteorder="little"))

        return len(rb)

    @api_call('CloseHandle', argc=1) # <-- More implementation
    def CloseHandle(self, emu, argv, ctx={}):
        '''
        BOOL CloseHandle(
          HANDLE hObject
        );
        '''
        hObject, = argv
        if emu.fs_manager.close_file(hObject):
            return True
        else:
            return False

    @api_call('CreateFileMapping', argc=6)
    def CreateFileMapping(self, emu, argv, ctx={}):
        '''
        HANDLE CreateFileMapping(
          HANDLE                hFile,
          LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
          DWORD                 flProtect,
          DWORD                 dwMaximumSizeHigh,
          DWORD                 dwMaximumSizeLow,
          LPTSTR                lpName
        );
        '''
        hfile, map_attrs, prot, max_size_high, max_size_low, map_name = argv

        cw = self.get_char_width(ctx)

        if prot & memdef.PAGE_TYPE.MEM_IMAGE:
            prot = memdef.PAGE_TYPE.MEM_IMAGE

        # Get to full map size
        map_size = (max_size_high << 32) | max_size_low

        name = ''
        if map_name:
            name = common.read_mem_string(emu.uc_eng, map_name, cw)
            argv[5] = name

        file_map = emu.fs_manager.create_file_mapping(hfile, map_size, prot, name)

        return file_map.handle_id

    @api_call('MapViewOfFile', argc=5)
    def MapViewOfFile(self, emu, argv, ctx={}):
        '''
        LPVOID MapViewOfFile(
          HANDLE hFileMappingObject,
          DWORD  dwDesiredAccess,
          DWORD  dwFileOffsetHigh,
          DWORD  dwFileOffsetLow,
          SIZE_T dwNumberOfBytesToMap
        );
        '''
        hFileMap, access, offset_high, offset_low, bytes_to_map = argv

        file_map = emu.fs_manager.file_handle_manager.get_mmfobj_by_handle_id(hFileMap)

        file_offset = (offset_high << 32) | offset_low
        
        # Lazy, Wasted mapping method
        if bytes_to_map > file_map.map_max:
            return 0xFFFFFFFF #

        map_region = emu.mem_manager.alloc_page(
                size=file_map.map_max,
                allocation_type=memdef.PAGE_ALLOCATION_TYPE.MEM_COMMIT,
                page_type=file_map.proetct
            )

        file_map = emu.fs_manager.create_map_object(hFileMap, file_offset, map_region)
        buf = emu.fs_manager.read_file(file_map.file_handle_id, bytes_to_map)
        emu.fs_manager.set_file_pointer(file_map.file_handle_id, file_offset)
        emu.uc_eng.mem_write(map_region.get_base_addr(), buf)

        Dispatcher.mmf_counter_tab[file_map.handle_id] = 0
        h = emu.uc_eng.hook_add(UC_HOOK_CODE, Dispatcher.file_map_dispatcher, (emu, file_map))
        file_map.set_dispatcher(h)

        return file_map.get_view_base()

    @api_call('UnmapViewOfFile', argc=1)
    def UnmapViewOfFile(self, emu, argv, ctx={}):
        '''
        BOOL UnmapViewOfFile(
          LPCVOID lpBaseAddress
        );
        '''
        lpBaseAddress, = argv
        file_map = emu.fs_manager.file_handle_manager.get_mmfobj_by_viewbase(lpBaseAddress)

        # dispatch all memory region
        view_base = file_map.get_view_base()
        map_max = file_map.map_max

        data = emu.uc_eng.mem_read(view_base, map_max) # Fixing the dispatch size as map_max may occur error.
        emu.fs_manager.write_file(file_map.file_handle_id, data)

        emu.fs_manager.set_file_pointer(
                file_map.file_handle_id, 
                file_map.get_file_offset()
            )

        h = file_map.get_dispatcher()
        emu.uc_eng.hook_del(h)
        emu.mem_manager.free_page(lpBaseAddress)

        file_map.view_region = None
        file_map.offset = -1
        file_map.set_dispatcher(-1)

        return True
    
    @api_call('VirtualAlloc', argc=4)
    def VirtualAlloc(self, emu, argv, ctx={}):
        '''LPVOID WINAPI VirtualAlloc(
          _In_opt_ LPVOID lpAddress,
          _In_     SIZE_T dwSize,
          _In_     DWORD  flAllocationType,
          _In_     DWORD  flProtect
        );'''

        lpAddress, dwSize, flAllocationType, flProtect = argv
        buf = 0
        tag_prefix = 'api.VirtualAlloc'

        page_region = emu.mem_manager.alloc_page(
                size=dwSize,
                allocation_type=flAllocationType,
                page_type=memdef.PAGE_TYPE.MEM_PRIVATE
            )
        

        return page_region.get_base_addr()

    @api_call('TerminateProcess', argc=2)
    def TerminateProcess(self, emu, argv, ctx={}):
        '''
        BOOL TerminateProcess(
            HANDLE hProcess,
            UINT   uExitCode
        );
        '''

        hProcess, uExitCode = argv
        rv = False

        proc = emu.get_object_from_handle(hProcess)
        if not proc:
            return rv

        emu.kill_process(proc)
        rv = True

    @api_call('FreeLibraryAndExitThread', argc=2)
    def FreeLibraryAndExitThread(self, emu, argv, ctx={}):
        '''
        void FreeLibraryAndExitThread(
            HMODULE hLibModule,
            DWORD   dwExitCode
        );
        '''
        emu.exit_process()
        return

    @api_call('ExitThread', argc=1)
    def ExitThread(self, emu, argv, ctx={}):
        '''
        void ExitThread(
            DWORD   dwExitCode
        );
        '''
        emu.exit_process()
        return

    @api_call('WinExec', argc=2)
    def WinExec(self, emu, argv, ctx={}):
        '''
        UINT WinExec(
            LPCSTR lpCmdLine,
            UINT   uCmdShow
        );
        '''

        lpCmdLine, uCmdShow = argv
        rv = 1

        if lpCmdLine:
            cmd = common.read_mem_string(emu.uc_eng, lpCmdLine, 1)
            argv[0] = cmd
            app = cmd.split()[0]
            #proc = emu.create_process(path=app, cmdline=cmd)
            #self.log_process_event(app, 'create')
            rv = 32

        return rv

    @api_call('GetSystemTimeAsFileTime', argc=1)
    def GetSystemTimeAsFileTime(self, emu, argv, ctx={}):
        '''void GetSystemTimeAsFileTime(
            LPFILETIME lpSystemTimeAsFileTime
        );'''

        lpSystemTimeAsFileTime, = argv
        ft = self.k32types.FILETIME(emu.get_ptr_size())
        import datetime
        timestamp = 116444736000000000 + int(datetime.datetime.utcnow().timestamp()) * 10000000
        ft.dwLowDateTime = 0xFFFFFFFF & timestamp
        ft.dwHighDateTime = timestamp >> 32

        emu.uc_eng.mem_write(lpSystemTimeAsFileTime, ft.get_bytes())

        return

    @api_call('GetCurrentThreadId', argc=0)
    def GetCurrentThreadId(self, emu, argv, ctx={}):
        '''DWORD GetCurrentThreadId();'''

        # implemet
        
        rv = 1

        return rv
    
    @api_call('GetCurrentProcessId', argc=0)
    def GetCurrentProcessId(self, emu, argv, ctx={}):
        '''DWORD GetCurrentProcessId();'''

        rv = 2

        return rv
    
    @api_call('QueryPerformanceCounter', argc=1)
    def QueryPerformanceCounter(self, emu, argv, ctx={}):
        '''BOOL WINAPI QueryPerformanceCounter(
          _Out_ LARGE_INTEGER *lpPerformanceCount
        );'''
        lpPerformanceCount, = argv

        rv = 1

        common.mem_write(emu.uc_eng, lpPerformanceCount, self.perf_counter.to_bytes(8, 'little'))
        return rv
    
    @api_call('IsProcessorFeaturePresent', argc=1,conv=cv.CALL_CONV_STDCALL)
    def IsProcessorFeaturePresent(self, emu, argv, ctx={}):
        '''BOOL IsProcessorFeaturePresent(
              DWORD ProcessorFeature
        );'''

        rv = 1

        lookup = {
            25: 'PF_ARM_64BIT_LOADSTORE_ATOMIC',
            24: 'PF_ARM_DIVIDE_INSTRUCTION_AVAILABLE',
            26: 'PF_ARM_EXTERNAL_CACHE_AVAILABLE',
            27: 'PF_ARM_FMAC_INSTRUCTIONS_AVAILABLE',
            18: 'PF_ARM_VFP_32_REGISTERS_AVAILABLE',
            7: 'PF_3DNOW_INSTRUCTIONS_AVAILABLE',
            16: 'PF_CHANNELS_ENABLED',
            2: 'PF_COMPARE_EXCHANGE_DOUBLE',
            14: 'PF_COMPARE_EXCHANGE128',
            15: 'PF_COMPARE64_EXCHANGE128',
            23: 'PF_FASTFAIL_AVAILABLE',
            1: 'PF_FLOATING_POINT_EMULATED',
            0: 'PF_FLOATING_POINT_PRECISION_ERRATA',
            3: 'PF_MMX_INSTRUCTIONS_AVAILABLE',
            12: 'PF_NX_ENABLED',
            9: 'PF_PAE_ENABLED',
            8: 'PF_RDTSC_INSTRUCTION_AVAILABLE',
            22: 'PF_RDWRFSGSBASE_AVAILABLE',
            20: 'PF_SECOND_LEVEL_ADDRESS_TRANSLATION',
            13: 'PF_SSE3_INSTRUCTIONS_AVAILABLE',
            21: 'PF_VIRT_FIRMWARE_ENABLED',
            6: 'PF_XMMI_INSTRUCTIONS_AVAILABLE',
            10: 'PF_XMMI64_INSTRUCTIONS_AVAILABLE',
            17: 'PF_XSAVE_ENABLED',
        }

        argv[0] = lookup[argv[0]]
        return rv

    @api_call('GetTempPath', argc=2)
    def GetTempPath(self, emu, argv, ctx={}):
        '''
        DWORD GetTempPathA(
        DWORD nBufferLength,
        LPSTR lpBuffer
        );
        '''

        nBufferLength, lpBuffer = argv
        rv = 0
        cw = common.get_char_width(ctx)
        tempdir = common.get_env(emu).get('temp', 'C:\\Windows\\temp\\')
        if cw == 2:
            new = (tempdir).encode('utf-16le') + b'\x00\x00'
        else:
            new = (tempdir).encode('utf-8') + b'\x00'
        rv = len(tempdir)
        if lpBuffer:
            argv[1] = tempdir
            emu.uc_eng.mem_write(lpBuffer, new)
        return rv

    @api_call('HeapCreate', argc=3)
    def HeapCreate(self, emu, argv, ctx={}):
        '''
        HANDLE HeapCreate(
          DWORD  flOptions,
          SIZE_T dwInitialSize,
          SIZE_T dwMaximumSize
        );
        '''

        flOptions, dwInitialSize, dwMaximumSize = argv

        heap = emu.mem_manager.create_heap(dwInitialSize, dwMaximumSize)

        return heap.heap_handle

    @api_call('HeapAlloc', argc=3)
    def HeapAlloc(self, emu, argv, ctx={}):
        '''
        DECLSPEC_ALLOCATOR LPVOID HeapAlloc(
          HANDLE hHeap,
          DWORD  dwFlags,
          SIZE_T dwBytes
        );
        '''

        hHeap, dwFlags, dwBytes = argv
        heap = emu.mem_manager.get_heap_by_handle(hHeap)
        pMem = emu.mem_manager.alloc_heap(heap, dwBytes)
        
        return pMem

    @api_call('HeapFree', argc=3)
    def HeapFree(self, emu, argv, ctx={}):
        '''
        BOOL HeapFree(
          HANDLE                 hHeap,
          DWORD                  dwFlags,
          _Frees_ptr_opt_ LPVOID lpMem
        );
        '''
        rv = 1
        hHeap, dwFlags, lpMem = argv

        heap = emu.mem_manager.get_heap_by_handle(hHeap)
        emu.mem_manager.free_heap(heap, lpMem)
        
        return rv

    @api_call('HeapDestroy', argc=1)
    def HeapDestroy(self, emu, argv, ctx={}):
        '''
        BOOL HeapDestroy(
          HANDLE hHeap
        );
        '''
        rv = 1
        hHeap, =  argv
        heap = emu.mem_manager.get_heap_by_handle(hHeap)
        emu.mem_manager.destroy_heap(heap)

        return True
    