# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# orca-eaa5a Edit
from pymanager import obj_manager
from pymanager.obj_manager import ObjectManager

from unicorn.x86_const import UC_X86_REG_ESP
from unicorn.unicorn_const import UC_HOOK_CODE
import pydll

import speakeasy.winenv.defs.windows.windows as windefs
import speakeasy.winenv.defs.windows.kernel32 as k32types
from cb_handler import ApiHandler
from cb_handler import CALL_CONV as cv
import common
import pymanager.defs.mem_defs as memdef
from cb_handler import Dispatcher


class Kernel32(ApiHandler):
    name = "kernel32"
    api_call = ApiHandler.api_call

    def __init__(self, proc):
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

    def normalize_res_identifier(self, proc, cw, val):
        mask = (16 ** (proc.get_ptr_size() // 2) - 1) << 16
        if val & mask:  # not an INTRESOURCE
            name = proc.read_mem_string(val, cw)
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
    def GetThreadLocale(self, proc, argv, ctx={}):
        '''
        LCID GetThreadLocale();
        '''
        return 0xC000

    @api_call('CreateThread', argc=6)
    def CreateThread(self, proc, argv, ctx={}):
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
        thread_handle = proc.emu.create_thread(
            proc,
            lpStartAddress, 
            lpParameter,
            stack_size,
            dwCreationFlags
            )
        thread_obj = proc.emu.obj_manager.get_obj_by_handle(thread_handle)

        if lpThreadId:
            proc.uc_eng.mem_write(lpThreadId, thread_obj.get_oid().to_bytes(4, 'little'))
        

        return thread_handle

    @api_call('ResumeThread', argc=1)
    def ResumeThread(self, proc, argv, ctx={}):
        '''
        DWORD ResumeThread(
            HANDLE hThread
        );
        '''
        thread_handle, = argv
        if thread_handle not in proc.threads:
            return 0xFFFFFFFF
        
        thread_obj =  proc.emu.obj_manager.get_obj_by_handle(thread_handle)

        import unicorn.x86_const as u_x86
        import struct

        thread_obj.suspend_count -= 1
        if thread_obj.suspend_count != 0: # resume thread
            return thread_obj.suspend_count
        

        proc.emu.switch_thread_context(proc, thread_obj)

        return thread_obj.suspend_count

    @api_call('WaitForSingleObject', argc=2)
    def WaitForSingleObject(self, proc, argv, ctx={}):
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
    def OutputDebugString(self, proc, argv, ctx={}):
        '''
        void OutputDebugStringA(
            LPCSTR lpOutputString
        );
        '''
        _str, = argv
        cw = common.get_char_width(ctx)
        argv[0] = common.read_mem_string(proc.uc_eng, _str, cw)

    @api_call('lstrlen', argc=1)
    def lstrlen(self, proc, argv, ctx={}):
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
        s = common.read_mem_string(proc.uc_eng, src, cw)

        argv[0] = s

        return len(s)

    @api_call('strlen', argc=1)
    def strlen(self, proc, argv, ctx={}):
        '''
        int strlen(
            LPCSTR lpString
        );
        '''
        return self.strlen(proc, argv, ctx)

    @api_call('GetThreadTimes', argc=5)
    def GetThreadTimes(self, proc, argv, ctx={}):
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
            common.mem_write(proc.uc_eng, lpCreationTime, b'\x20\x20\x00\x00')
        return True

    @api_call('GetProcessHeap', argc=0)
    def GetProcessHeap(self, proc, argv, ctx={}):
        '''
        HANDLE GetProcessHeap();
        '''
        return proc.proc_default_heap.address

    @api_call('GetProcessVersion', argc=1)
    def GetProcessVersion(self, proc, argv, ctx={}):
        '''
        DWORD GetProcessVersion(
            DWORD ProcessId
        );
        '''

        ver = proc.proc_os_v
        major = ver['major']
        minor = ver['minor']

        rv = 0xFFFFFFFF & (major << 16 | minor)

        return rv

    @api_call('DisableThreadLibraryCalls', argc=1)
    def DisableThreadLibraryCalls(self, proc, argv, ctx={}):
        '''
        BOOL DisableThreadLibraryCalls(
            HMODULE hLibModule
        );
        '''

        hLibModule, = argv

        return True

    @api_call('LoadLibrary', argc=1)
    def LoadLibrary(self, proc, argv, ctx={}):
        '''HMODULE LoadLibrary(
            LPTSTR lpLibFileName
        );'''

        pLib_name, = argv
        hmod = windefs.NULL

        cw = common.get_char_width(ctx)
        mod_name = common.read_mem_string(proc.uc_eng, pLib_name, cw)
        mod_name = ApiHandler.api_set_schema(mod_name)

        return proc.emu.load_library(mod_name)

    @api_call('LoadLibraryEx', argc=3)
    def LoadLibraryEx(self, proc, argv, ctx={}):
        '''HMODULE LoadLibraryExA(
            LPCSTR lpLibFileName,
            HANDLE hFile,
            DWORD  dwFlags
        );'''

        pLib_name, _, dwFlags = argv

        cw = common.get_char_width(ctx)
        lib_name = common.read_mem_string(proc.uc_eng, pLib_name, cw)
        lib_name = ApiHandler.api_set_schema(lib_name)
        hmod = proc.load_library(lib_name)

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

        return hmod

    @api_call('GetModuleHandleEx', argc=3)
    def GetModuleHandleEx(self, proc, argv, ctx={}):
        '''
        BOOL GetModuleHandleExA(
            DWORD   dwFlags,
            LPCSTR  lpModuleName,
            HMODULE *phModule
        );
        '''
        dwFlags, lpModuleName, phModule = argv

        hmod = self.GetModuleHandle(proc, [lpModuleName], ctx)
        if phModule:
            _mod = (hmod).to_bytes(proc.get_ptr_size(), 'little')
            proc.uc_eng.mem_write(phModule, _mod)
        return hmod

    @api_call('GetModuleHandle', argc=1)
    def GetModuleHandle(self, proc, argv, ctx={}):
        '''
        HMODULE GetModuleHandle(
            LPCSTR lpModuleName
        );
        '''

        mod_name, = argv

        cw = self.get_char_width(ctx)
        rv = 0

        if not mod_name:
            rv = proc.image_base
        else:
            lib = common.read_mem_string(proc.uc_eng, mod_name, cw)
            if lib not in proc.imp:
                lib = ApiHandler.api_set_schema(lib)
            if lib in proc.imp:
                rv = pydll.SYSTEM_DLL_BASE[lib]
            else:
                rv = 0
                
        return rv

    @api_call('GetModuleFileName', argc=3)
    def GetModuleFileName(self, proc, argv, ctx={}):
        '''
        DWORD GetModuleFileName(
            HMODULE hModule,
            LPSTR   lpFilename,
            DWORD   nSize
        );
        '''
        module_handle, pBuf, size = argv
        mod_name = ""
        for _mod_name in proc.imports:
            mod_base = pydll.SYSTEM_DLL_BASE[mod_name]
            if mod_base == module_handle:
                mod_name = _mod_name
                break
        if mod_name == "":
            return 0x7a # ERROR_INSUFFICIENT_BUFFER
        cw = self.get_char_width(ctx)
        if size < len(mod_name):
            mod_name = mod_name[:size]
        common.write_mem_string(proc.uc_eng, mod_name, pBuf, cw)
        
        return len(mod_name)

    @api_call('GetTickCount', argc=0)
    def GetTickCount(self, proc, argv, ctx={}):
        '''
        DWORD GetTickCount();
        '''

        self.tick_counter += 20

        return self.tick_counter

    @api_call('GetTickCount64', argc=0)
    def GetTickCount64(self, proc, argv, ctx={}):
        '''
        DWORD GetTickCount();
        '''
        self.GetTickCount(proc, argv, ctx)

        return self.tick_counter

    @api_call('CreateFile', argc=7)
    def CreateFile(self, proc, argv, ctx={}):
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
        f_name = common.read_mem_string(proc.uc_eng, pFileName, cw)
        py_io_mode = proc.emu.fs_manager.convert_io_mode(f_name, access, disp)

        file_handle = proc.emu.fs_manager.create_file(f_name, py_io_mode)

        return file_handle

    @api_call('WriteFile', argc=5)
    def WriteFile(self, proc, argv, ctx={}):
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
        
        data = proc.uc_eng.mem_read(lpBuffer, num_bytes)
        rv = proc.emu.fs_manager.write_file(hFile, data)
        proc.uc_eng.mem_write(pBytesWritten, rv.to_bytes(proc.ptr_size, byteorder="little"))

        return rv

    @api_call('ReadFile', argc=5)
    def ReadFile(self, proc, argv, ctx={}):
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

        rb = proc.emu.fs_manager.read_file(hFile, num_bytes)
        proc.uc_eng.mem_write(lpBuffer, rb)
        proc.uc_eng.mem_write(lpBytesRead, len(rb).to_bytes(proc.ptr_size, byteorder="little"))

        return len(rb)

    @api_call('CloseHandle', argc=1) # <-- More implementation
    def CloseHandle(self, proc, argv, ctx={}):
        '''
        BOOL CloseHandle(
          HANDLE hObject
        );
        '''
        hObject, = argv
        if proc.emu.fs_manager.close_file(hObject):
            return True
        else:
            return False

    @api_call('CreateFileMapping', argc=6)
    def CreateFileMapping(self, proc, argv, ctx={}):
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
            name = common.read_mem_string(proc.uc_eng, map_name, cw)
            argv[5] = name

        mmf_handle = proc.emu.fs_manager.create_file_mapping(hfile, map_size, prot, name)

        return mmf_handle

    @api_call('MapViewOfFile', argc=5)
    def MapViewOfFile(self, proc, argv, ctx={}):
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

        file_map_obj = obj_manager.ObjectManager.get_obj_by_handle(hFileMap)

        file_offset = (offset_high << 32) | offset_low
        
        # Lazy, Wasted mapping method
        if bytes_to_map > file_map_obj.map_max:
            return 0xFFFFFFFF #

        map_region = proc.vas_manager.alloc_page(
                size=file_map_obj.map_max,
                allocation_type=memdef.PAGE_ALLOCATION_TYPE.MEM_COMMIT,
                page_type=file_map_obj.proetct
            )

        file_map = proc.emu.fs_manager.set_map_object(hFileMap, file_offset, map_region)
        buf = proc.emu.fs_manager.read_file(file_map.handle, bytes_to_map)
        proc.emu.fs_manager.set_file_pointer(file_map.handle, file_offset)
        proc.uc_eng.mem_write(map_region.get_base_addr(), buf)

        Dispatcher.mmf_counter_tab[file_map.handle] = 0
        h = proc.uc_eng.hook_add(UC_HOOK_CODE, Dispatcher.file_map_dispatcher, (proc.emu, file_map))
        file_map.set_dispatcher(h)

        return file_map.get_view_base()

    @api_call('UnmapViewOfFile', argc=1)
    def UnmapViewOfFile(self, proc, argv, ctx={}):
        '''
        BOOL UnmapViewOfFile(
          LPCVOID lpBaseAddress
        );
        '''
        lpBaseAddress, = argv
        file_map_obj = proc.emu.fs_manager.file_handle_manager.get_mmfobj_by_viewbase(lpBaseAddress)

        # dispatch all memory region
        view_base = file_map_obj.get_view_base()
        map_max = file_map_obj.map_max

        data = proc.uc_eng.mem_read(view_base, map_max) # Fixing the dispatch size as map_max may occur error.
        proc.emu.fs_manager.write_file(file_map_obj.file_handle, data)

        proc.emu.fs_manager.set_file_pointer(
                file_map_obj.file_handle, 
                file_map_obj.get_file_offset()
            )

        h = file_map_obj.get_dispatcher()
        proc.uc_eng.hook_del(h)
        proc.vas_manager.free_page(lpBaseAddress)

        file_map_obj.view_region = None
        file_map_obj.offset = -1
        file_map_obj.set_dispatcher(-1)

        return True
    
    @api_call('VirtualAlloc', argc=4)
    def VirtualAlloc(self, proc, argv, ctx={}):
        '''LPVOID WINAPI VirtualAlloc(
          _In_opt_ LPVOID lpAddress,
          _In_     SIZE_T dwSize,
          _In_     DWORD  flAllocationType,
          _In_     DWORD  flProtect
        );'''

        lpAddress, dwSize, flAllocationType, flProtect = argv
        buf = 0
        tag_prefix = 'api.VirtualAlloc'

        page_region = proc.vas_manager.alloc_page(
                size=dwSize,
                allocation_type=flAllocationType,
                page_type=memdef.PAGE_TYPE.MEM_PRIVATE,
                alloc_base=lpAddress
            )
        

        return page_region.get_base_addr()

    @api_call('VirtualAllocEx', argc=5)
    def VirtualAllocEx(self, proc, argv, ctx={}):
        '''
        LPVOID VirtualAllocEx(
            HANDLE hProcess,
            LPVOID lpAddress,
            SIZE_T dwSize,
            DWORD  flAllocationType,
            DWORD  flProtect
        );
        '''
        proc_handle, base_addr, size, alloc_type, protection = argv
        targ_proc_obj = obj_manager.ObjectManager.get_obj_by_handle(proc_handle)
        page_region = targ_proc_obj.vas_manager.alloc_page(
                size=size,
                allocation_type=alloc_type,
                page_type=memdef.PAGE_TYPE.MEM_PRIVATE,
                alloc_base=base_addr
            )
        return page_region.get_base_addr()
    
    @api_call('VirtualFree', argc=3)
    def VirtualFree(self, proc, argv, ctx={}):
        '''
        BOOL VirtualFree(
            LPVOID lpAddress,
            SIZE_T dwSize,
            DWORD  dwFreeType
        );
        '''
        # Implement decommit only
        base_addr, size, ftype = argv
        proc.vas_manager.free_page(base_addr, size)
        
        return True

    @api_call('VirtualFreeEx', argc=4)
    def VirtualFreeEx(self, proc, argv, ctx={}):
        '''
        BOOL VirtualFreeEx(
            HANDLE hProcess,
            LPVOID lpAddress,
            SIZE_T dwSize,
            DWORD  dwFreeType
        );
        '''
        proc_handle, base_addr, size, ftype = argv
        targ_proc_obj = obj_manager.ObjectManager.get_obj_by_handle(proc_handle)
        targ_proc_obj.vas_manager.free_page(base_addr, size)

        return True
    @api_call('VirtualProtect', argc=4)
    def VirtualProtect(self, proc, argv, ctx={}):
        '''
        BOOL VirtualProtect(
            LPVOID lpAddress,
            SIZE_T dwSize,
            DWORD  flNewProtect,
            PDWORD lpflOldProtect
        );
        '''
        return True
    
    @api_call('VirtualProtectEx', argc=4)
    def VirtualProtectEx(self, proc, argv, ctx={}):
        '''
        BOOL VirtualProtect(
            HANDLE hProcess
            LPVOID lpAddress,
            SIZE_T dwSize,
            DWORD  flNewProtect,
            PDWORD lpflOldProtect
        );
        '''
        return True
    
    
    @api_call('VirtualQuery', argc=3)
    def VirtualQuery(self, proc, argv, ctx={}):
        '''
        SIZE_T VirtualQuery(
            LPCVOID                   lpAddress,
            PMEMORY_BASIC_INFORMATION lpBuffer,
            SIZE_T                    dwLength
        );
        '''
        base_addr, pMbi, size = argv
        mbi = k32types.MEMORY_BASIC_INFORMATION(proc.ptr_size)
        targ_pg_rg = proc.vas_manager.get_page_region_from_baseaddr(base_addr)
        mbi.AllocationBase = targ_pg_rg.base_address
        mbi.AllocationProtect = memdef.PAGE_PROTECT.PAGE_EXECUTE_READWRITE
        mbi.State = memdef.PAGE_ALLOCATION_TYPE.MEM_COMMIT
        mbi.RegionSize = targ_pg_rg.size
        mbi.Type = targ_pg_rg.page_type

        proc.mem_write(pMbi, mbi.get_bytes())

        return mbi.sizeof()

    @api_call('VirtualQueryEx', argc=3)
    def VirtualQueryEx(self, proc, argv, ctx={}):
        '''
        SIZE_T VirtualQueryEx(
            HANDLE                    hProcess
            LPCVOID                   lpAddress,
            PMEMORY_BASIC_INFORMATION lpBuffer,
            SIZE_T                    dwLength
        );
        '''
        proc_handle, base_addr, pMbi, size = argv
        targ_proc_obj = obj_manager.ObjectManager.get_obj_by_handle(proc_handle)
        mbi = k32types.MEMORY_BASIC_INFORMATION(proc.ptr_size)
        targ_pg_rg = targ_proc_obj.vas_manager.get_page_region_from_baseaddr(base_addr)
        mbi.AllocationBase = targ_pg_rg.base_address
        mbi.AllocationProtect = memdef.PAGE_PROTECT.PAGE_EXECUTE_READWRITE
        mbi.State = memdef.PAGE_ALLOCATION_TYPE.MEM_COMMIT
        mbi.RegionSize = targ_pg_rg.size
        mbi.Type = targ_pg_rg.page_type

        targ_proc_obj.mem_write(pMbi, mbi.get_bytes())

        return mbi.sizeof()

    @api_call('WriteProcessMemory', argc=5)
    def WriteProcessMemory(self, proc, argv, ctx={}):
        '''
        BOOL WriteProcessMemory(
            HANDLE  hProcess,
            LPVOID  lpBaseAddress,
            LPCVOID lpBuffer,
            SIZE_T  nSize,
            SIZE_T  *lpNumberOfBytesWritten
        );
        '''
        proc_handle, base_addr, pData, size, pWritten_sz = argv
        targ_proc_obj = obj_manager.ObjectManager.get_obj_by_handle(proc_handle)

        raw_data = targ_proc_obj.uc_eng.mem_read(pData, size)
        targ_proc_obj.uc_eng.mem_write(base_addr, raw_data)
        proc.uc_eng.mem_write(pWritten_sz, len(raw_data).to_bytes(4,'little'))

        page_region = targ_proc_obj.vas_manager.alloc_page(
                size=dwSize,
                allocation_type=flAllocationType,
                page_type=memdef.PAGE_TYPE.MEM_PRIVATE
            )
        

        return 0x1

    @api_call('TerminateProcess', argc=2)
    def TerminateProcess(self, proc, argv, ctx={}):
        '''
        BOOL TerminateProcess(
            HANDLE hProcess,
            UINT   uExitCode
        );
        '''

        hProcess, uExitCode = argv
        rv = False

        proc = proc.get_object_from_handle(hProcess)
        if not proc:
            return rv

        proc.kill_process(proc)
        rv = True

    @api_call('FreeLibraryAndExitThread', argc=2)
    def FreeLibraryAndExitThread(self, proc, argv, ctx={}):
        '''
        void FreeLibraryAndExitThread(
            HMODULE hLibModule,
            DWORD   dwExitCode
        );
        '''
        proc.exit_process()
        return

    @api_call('ExitThread', argc=1)
    def ExitThread(self, proc, argv, ctx={}):
        '''
        void ExitThread(
            DWORD   dwExitCode
        );
        '''
        proc.exit_process()
        return

    @api_call('WinExec', argc=2)
    def WinExec(self, proc, argv, ctx={}):
        '''
        UINT WinExec(
            LPCSTR lpCmdLine,
            UINT   uCmdShow
        );
        '''

        lpCmdLine, uCmdShow = argv
        rv = 1

        if lpCmdLine:
            cmd = common.read_mem_string(proc.uc_eng, lpCmdLine, 1)
            argv[0] = cmd
            app = cmd.split()[0]
            #proc = proc.create_process(path=app, cmdline=cmd)
            #self.log_process_event(app, 'create')
            rv = 32

        return rv

    @api_call('GetSystemTimeAsFileTime', argc=1)
    def GetSystemTimeAsFileTime(self, proc, argv, ctx={}):
        '''void GetSystemTimeAsFileTime(
            LPFILETIME lpSystemTimeAsFileTime
        );'''

        lpSystemTimeAsFileTime, = argv
        ft = self.k32types.FILETIME(proc.get_ptr_size())
        import datetime
        timestamp = 116444736000000000 + int(datetime.datetime.utcnow().timestamp()) * 10000000
        ft.dwLowDateTime = 0xFFFFFFFF & timestamp
        ft.dwHighDateTime = timestamp >> 32

        proc.uc_eng.mem_write(lpSystemTimeAsFileTime, ft.get_bytes())

        return

    @api_call('GetCurrentThreadId', argc=0)
    def GetCurrentThreadId(self, proc, argv, ctx={}):
        '''DWORD GetCurrentThreadId();'''

        # implemet
        
        rv = 1

        return rv
    
    @api_call('GetCurrentProcessId', argc=0)
    def GetCurrentProcessId(self, proc, argv, ctx={}):
        '''DWORD GetCurrentProcessId();'''

        rv = 2

        return rv
    
    @api_call('QueryPerformanceCounter', argc=1)
    def QueryPerformanceCounter(self, proc, argv, ctx={}):
        '''BOOL WINAPI QueryPerformanceCounter(
          _Out_ LARGE_INTEGER *lpPerformanceCount
        );'''
        lpPerformanceCount, = argv

        rv = 1

        common.mem_write(proc.uc_eng, lpPerformanceCount, self.perf_counter.to_bytes(8, 'little'))
        return rv
    
    @api_call('IsProcessorFeaturePresent', argc=1,conv=cv.CALL_CONV_STDCALL)
    def IsProcessorFeaturePresent(self, proc, argv, ctx={}):
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
            1: 'PF_FLOATING_POINT_procLATED',
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
    def GetTempPath(self, proc, argv, ctx={}):
        '''
        DWORD GetTempPathA(
        DWORD nBufferLength,
        LPSTR lpBuffer
        );
        '''

        nBufferLength, lpBuffer = argv
        rv = 0
        cw = common.get_char_width(ctx)
        tempdir = common.get_env(proc.emu).get('temp', 'C:\\Windows\\temp\\')
        if cw == 2:
            new = (tempdir).encode('utf-16le') + b'\x00\x00'
        else:
            new = (tempdir).encode('utf-8') + b'\x00'
        rv = len(tempdir)
        if lpBuffer:
            argv[1] = tempdir
            proc.uc_eng.mem_write(lpBuffer, new)
        return rv

    @api_call('HeapCreate', argc=3)
    def HeapCreate(self, proc, argv, ctx={}):
        '''
        HANDLE HeapCreate(
            DWORD  flOptions,
            SIZE_T dwInitialSize,
            SIZE_T dwMaximumSize
        );
        '''

        flOptions, dwInitialSize, dwMaximumSize = argv

        heap = proc.vas_manager.create_heap(dwInitialSize, dwMaximumSize)

        return heap.handle

    @api_call('HeapAlloc', argc=3)
    def HeapAlloc(self, proc, argv, ctx={}):
        '''
        DECLSPEC_ALLOCATOR LPVOID HeapAlloc(
          HANDLE hHeap,
          DWORD  dwFlags,
          SIZE_T dwBytes
        );
        '''

        hHeap, dwFlags, dwBytes = argv
        heap = proc.emu.obj_manager.get_obj_by_handle(hHeap)
        pMem = proc.vas_manager.alloc_heap(heap, dwBytes)
        
        return pMem

    @api_call('HeapFree', argc=3)
    def HeapFree(self, proc, argv, ctx={}):
        '''
        BOOL HeapFree(
          HANDLE                 hHeap,
          DWORD                  dwFlags,
          _Frees_ptr_opt_ LPVOID lpMem
        );
        '''
        rv = 1
        hHeap, dwFlags, lpMem = argv
        proc.vas_manager.free_heap(hHeap, lpMem)
        
        return rv

    @api_call('HeapDestroy', argc=1)
    def HeapDestroy(self, proc, argv, ctx={}):
        '''
        BOOL HeapDestroy(
          HANDLE hHeap
        );
        '''
        rv = 1
        hHeap, =  argv
        proc.vas_manager.destroy_heap(hHeap)

        return True
    
    @api_call('LocalAlloc', argc=2)
    def LocalAlloc(self, proc, argv, ctx={}):
        '''
        DECLSPEC_ALLOCATOR HLOCAL LocalAlloc(
            UINT   uFlags,
            SIZE_T uBytes
        );
        '''
        flag, size = argv

        pMem = proc.vas_manager.alloc_heap(proc.proc_default_heap, size)
        hnd = obj_manager.ObjectManager.create_new_object(obj_manager.EmLMEM, pMem, size, flag)
        if flag and 0x0: # LMEM_FIXED
            lMem_obj = obj_manager.ObjectManager.get_obj_by_handle(hnd)
            lMem_obj.handle = hnd
        
        return hnd
    
    @api_call('LocalLock', argc=1)
    def LocalLock(self, proc, argv, ctx={}):
        '''
        LPVOID LocalLock(
            HLOCAL hMem
        );
        '''
        lmem_handle, = argv
        lMem_obj = obj_manager.ObjectManager.get_obj_by_handle(lmem_handle)
        return lMem_obj.base
    

    @api_call('LocalFlags', argc=1)
    def LocalFlags(self, proc, argv, ctx={}):
        '''
        UINT LocalFlags(
            HLOCAL hMem
        );
        '''
        lmem_handle, = argv
        lMem_obj = obj_manager.ObjectManager.get_obj_by_handle(lmem_handle)
        
        return lMem_obj.flags
    
    @api_call('LocalSize', argc=1)
    def LocalSize(self, proc, argv, ctx={}):
        '''
        SIZE_T LocalSize(
            HLOCAL hMem
        );
        '''
        lmem_handle, = argv
        lMem_obj = obj_manager.ObjectManager.get_obj_by_handle(lmem_handle)
        
        return lMem_obj.size

    @api_call('LocalFree', argc=1)
    def LocalFree(self, proc, argv, ctx={}):
        '''
        HLOCAL LocalFree(
            _Frees_ptr_opt_ HLOCAL hMem
        );
        '''
        lmem_handle, = argv
        lMem_obj = obj_manager.ObjectManager.get_obj_by_handle(lmem_handle)
        proc.vas_manager.free_heap(proc.proc_default_heap, lMem_obj.base)

        return 0

    @api_call('CreateProcess', argc=10)
    def CreateProcess(self, proc, argv, ctx={}):
        '''BOOL CreateProcess(
            LPTSTR                lpApplicationName,
            LPTSTR                lpCommandLine,
            LPSECURITY_ATTRIBUTES lpProcessAttributes,
            LPSECURITY_ATTRIBUTES lpThreadAttributes,
            BOOL                  bInheritHandles,
            DWORD                 dwCreationFlags,
            LPVOID                lpEnvironment,
            LPTSTR                lpCurrentDirectory,
            LPSTARTUPINFO         lpStartupInfo,
            LPPROCESS_INFORMATION lpProcessInformation
        );'''
        app, cmd, pa, ta, inherit, flags, env, cd, si, ppi = argv

        cw = self.get_char_width(ctx)
        cmdstr = ''
        appstr = ''
        if app:
            appstr = common.read_mem_string(proc.uc_eng, app, cw)
            argv[0] = appstr
        if cmd:
            cmdstr = common.read_mem_string(proc.uc_eng, cmd, cw)
            argv[1] = cmdstr

        if not appstr and cmdstr:
            appstr = cmdstr
        elif appstr and cmdstr:
            appstr += " "+cmdstr # cmdstr be param
        elif appstr and not cmdstr:
            pass
        else:
            return 0
        # child proc can't be inherited
        
        new_proc_obj = proc.emu.create_process(appstr)
        main_thread = obj_manager.ObjectManager.get_obj_by_handle(new_proc_obj.threads[-1])
        proc.emu.push_wait_queue(new_proc_obj)

        _pi = self.k32types.PROCESS_INFORMATION(proc.ptr_size)
        data = common.mem_cast(proc.uc_eng, _pi, ppi)
        _pi.hProcess = new_proc_obj.handle
        _pi.hThread = main_thread.handle
        _pi.dwProcessId = new_proc_obj.pid
        _pi.dwThreadId = main_thread.tid

        proc.uc_eng.mem_write(ppi, common.get_bytes(data))

        rv = 1

        return rv

    @api_call('ExitProcess', argc=1)
    def ExitProcess(self, proc, argv, ctx={}):
        '''
        void ExitProcess(
            UINT uExitCode
        );
        '''
        proc.emu_suspend_flag = True
        return
