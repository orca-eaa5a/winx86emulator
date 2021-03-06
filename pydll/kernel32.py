# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# orca-eaa5a Edit

from unicorn.unicorn_const import UC_HOOK_MEM_WRITE

import pydll
import common
from uc_handler.api_handler import ApiHandler
from uc_handler.api_handler import CALL_CONV as cv
from uc_handler.dispatcher import Dispatcher

from pymanager.objmanager.manager import ObjectManager
from pyemulator import EmuThreadManager, EmuProcManager
from pymanager.fsmanager.fs_emu_util import *
from speakeasy.windows.nt.ddk import GENERIC_ALL

import speakeasy.windows.windows.kernel32 as k32types
import speakeasy.windows.windows.windows as win_const
from pymanager.memmanager.windefs import *


class Kernel32(ApiHandler):
    name = "kernel32"
    api_call = ApiHandler.api_call

    def __init__(self, win_emu):
        self.win_emu = win_emu
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

    def normalize_res_identifier(self, proc, cw, val):
        mask = (16 ** (proc.get_ptr_size() // 2) - 1) << 16
        if val & mask:  # not an INTRESOURCE
            name = proc.read_string(val, cw)
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
        thread_handle = self.win_emu.create_thread(
            proc,
            lpStartAddress, 
            lpParameter,
            stack_size,
            dwCreationFlags
            )
        thread_obj = self.win_emu.obj_manager.get_obj_by_handle(thread_handle)

        if lpThreadId:
            proc.write_mem_self(lpThreadId, thread_obj.get_oid().to_bytes(4, 'little'))
        

        return thread_handle

    @api_call('CreateRemoteThread', argc=7)
    def CreateRemoteThread(self, proc, argv, ctx={}):
        """
        HANDLE CreateRemoteThread(
            [in]  HANDLE                 hProcess,
            [in]  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
            [in]  SIZE_T                 dwStackSize,
            [in]  LPTHREAD_START_ROUTINE lpStartAddress,
            [in]  LPVOID                 lpParameter,
            [in]  DWORD                  dwCreationFlags,
            [out] LPDWORD                lpThreadId
        );
        """
        hProc, lpThreadAttributes, stack_size, lpStartAddr, lpParam, creationFlags, lpThreadId = argv
        proc_obj = self.win_emu.obj_manager.get_obj_by_handle(hProc)
        hThread = self.win_emu.create_thread(
            proc_obj,
            lpStartAddr, 
            lpParam,
            stack_size,
            creationFlags
            )
        thread_obj = self.win_emu.obj_manager.get_obj_by_handle(hThread)

        if lpThreadId:
            proc.write_mem_self(lpThreadId, thread_obj.get_oid().to_bytes(4, 'little'))
        
        return hThread

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
        
        thread_obj =  self.win_emu.obj_manager.get_obj_by_handle(thread_handle)

        import unicorn.x86_const as u_x86
        import struct

        thread_obj.suspend_count -= 1
        if thread_obj.suspend_count != 0: # resume thread
            return thread_obj.suspend_count
        
        self.win_emu.switch_thread_context(proc, thread_obj)

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
            rv = win_const.WAIT_TIMEOUT
        else:
            rv = win_const.WAIT_OBJECT_0

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
        argv[0] = proc.read_string(_str, cw)

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
        s = proc.read_string(src, cw)

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
            proc.write_mem_self(lpCreationTime, b'\x20\x20\x00\x00')
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
        hmod = win_const.NULL

        cw = common.get_char_width(ctx)
        mod_name = proc.read_string(pLib_name, cw)
        mod_name = ApiHandler.api_set_schema(mod_name)

        return self.win_emu.load_library(mod_name)

    @api_call('LoadLibraryEx', argc=3)
    def LoadLibraryEx(self, proc, argv, ctx={}):
        '''HMODULE LoadLibraryExA(
            LPCSTR lpLibFileName,
            HANDLE hFile,
            DWORD  dwFlags
        );'''

        pLib_name, _, dwFlags = argv

        cw = common.get_char_width(ctx)
        lib_name = proc.read_string(pLib_name, cw)
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
            proc.write_mem_self(phModule, _mod)
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
            lib = proc.read_string(mod_name, cw)
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
        proc.write_string(pBuf, mod_name, cw)
        
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
        
        # ADD:
        # convert pFileName to full path

        cw = common.get_char_width(ctx)
        f_name = proc.read_string(pFileName, cw)
        
        volume_name, path, file_name = parse_file_fullpath(f_name)
        if not volume_name:
            # this is relative path
            f_name = emu_path_join(self.win_emu.emu_home_dir, f_name)
            fp = convert_winpath_to_emupath(f_name)
            f_name = emu_path_join(fp["vl"], fp["ps"])

        hFile = self.win_emu.obj_manager.get_object_handle('File', f_name, access, disp, share, flags)

        return hFile

    @api_call('GetLastError', argc=0)
    def GetLastError(self, proc, argv, ctx={}):
        return 0

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
        
        data = proc.read_mem_self(lpBuffer, num_bytes)
        file_obj = self.win_emu.obj_manager.get_obj_by_handle(hFile)
        wf = file_obj.im_write_file(data)
        proc.write_mem_self(pBytesWritten, rv.to_bytes(proc.ptr_size, byteorder="little"))

        return wf["ws"]

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
        file_obj = self.win_emu.obj_manager.get_obj_by_handle(hFile)
        rf = file_obj.im_read_file(num_bytes)
        
        proc.write_mem_self(lpBuffer, rf["data"])
        proc.write_mem_self(lpBytesRead, len(rf["data"]).to_bytes(proc.ptr_size, byteorder="little"))

        return rf["rs"]

    @api_call('CloseHandle', argc=1) # <-- More implementation
    def CloseHandle(self, proc, argv, ctx={}):
        '''
        BOOL CloseHandle(
          HANDLE hObject
        );
        '''
        hObject, = argv
        if self.win_emu.obj_manager.close_handle(hObject):
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
        hFile, map_attrs, prot, max_size_high, max_size_low, map_name = argv

        cw = self.get_char_width(ctx)

        if prot & PageType.MEM_IMAGE:
            prot = PageType.MEM_IMAGE

        # Get to full map size

        name = ''

        if hFile == win_const.INVALID_HANDLE_VALUE:
            # page file
            import random
            hFile = self.win_emu.obj_manager.get_object_handle(
                'File', 
                'c:/mmf'+str(random.randint(0, 0x1000)),
                win_const.GENERIC_ALL,
                win_const.CREATE_ALWAYS,
                0, 
                win_const.FILE_ATTRIBUTE_NORMAL
            )
            pass
        if map_name:
            name = proc.read_string(map_name, cw)
        file_obj = self.win_emu.obj_manager.get_obj_by_handle(hFile)
        hFileMap = self.win_emu.obj_manager.get_object_handle(
            'MMFile',
            file_obj,
            map_attrs,
            prot,
            max_size_high,
            max_size_low,
            name
        )

        return hFileMap

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

        fmap_obj = ObjectManager.get_obj_by_handle(hFileMap)
        
        if bytes_to_map > fmap_obj.maximum_size:
            return win_const.INVALID_HANDLE_VALUE #

        map_region = self.win_emu.mem_manager.alloc_page(
                pid=proc.pid,
                size=fmap_obj.maximum_size,
                allocation_type=PageAllocationType.MEM_COMMIT,
                page_type=fmap_obj.protect
            )

        mf = fmap_obj.map_memory_with_file(
            map_region.get_base_addr(),
            offset_high,
            offset_low,
            bytes_to_map
        )
        if not mf["success"]:
            return win_const.INVALID_HANDLE_VALUE
        
        map_region.set_mmf_handle(hFileMap)
        proc.write_mem_self(map_region.get_base_addr(), mf["data"])

        Dispatcher.mmf_counter_tab[hFileMap] = 0
        h = proc.uc_eng.hook_add(UC_HOOK_MEM_WRITE, Dispatcher.file_map_dispatcher, (proc, fmap_obj))
        fmap_obj.set_dispatcher(h)

        return map_region.get_base_addr()

    @api_call('UnmapViewOfFile', argc=1)
    def UnmapViewOfFile(self, proc, argv, ctx={}):
        '''
        BOOL UnmapViewOfFile(
          LPCVOID lpBaseAddress
        );
        '''
        lpBaseAddress, = argv
        page_region = self.win_emu.mem_manager.get_page_region_from_baseaddr(proc.pid, lpBaseAddress)
        hMapFile = page_region.get_mmf_handle()
        if hMapFile == win_const.INVALID_HANDLE_VALUE:
            return False
        fmap_obj = self.win_emu.obj_manager.get_obj_by_handle(hMapFile)
        Dispatcher.fetch_all_region(proc.uc_eng, fmap_obj)

        proc.uc_eng.hook_del(fmap_obj.dispatcher)

        self.win_emu.mem_manager.free_page(proc.pid, lpBaseAddress)
        fmap_obj.unmap_memory_with_file()

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

        page_region = self.win_emu.mem_manager.alloc_page(proc.pid,
                size=dwSize,
                allocation_type=flAllocationType,
                page_type=PageType.MEM_PRIVATE,
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
        targ_proc_obj = ObjectManager.get_obj_by_handle(proc_handle)
        page_region = self.win_emu.mem_manager.alloc_page(
                pid=targ_proc_obj.pid,
                size=size,
                allocation_type=alloc_type,
                page_type=PageType.MEM_PRIVATE,
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
        self.win_emu.mem_manager.free_page(proc.pid, base_addr, size)
        
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
        targ_proc_obj = ObjectManager.get_obj_by_handle(proc_handle)
        self.win_emu.mem_manager.free_page(targ_proc_obj.pid, base_addr, size)

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
        targ_pg_rg = self.win_emu.mem_manager.get_page_region_from_baseaddr(proc.pid, base_addr)
        mbi.AllocationBase = targ_pg_rg.base_address
        mbi.AllocationProtect = PageProtect.PAGE_EXECUTE_READWRITE
        mbi.State = PageAllocationType.MEM_COMMIT
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
        targ_proc_obj = ObjectManager.get_obj_by_handle(proc_handle)
        mbi = k32types.MEMORY_BASIC_INFORMATION(proc.ptr_size)
        targ_pg_rg = self.win_emu.mem_manager.get_page_region_from_baseaddr(targ_proc_obj, base_addr)
        mbi.AllocationBase = targ_pg_rg.base_address
        mbi.AllocationProtect = PageProtect.PAGE_EXECUTE_READWRITE
        mbi.State = PageAllocationType.MEM_COMMIT
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
        proc_handle, base_addr, pData, dwSize, pWritten_sz = argv
        targ_proc_obj = ObjectManager.get_obj_by_handle(proc_handle)

        raw_data = proc.read_mem_self(pData, dwSize)
        targ_proc_obj.write_mem_self(base_addr, bytes(raw_data))
        proc.write_mem_self(pWritten_sz, len(raw_data).to_bytes(4,'little'))
        

        return 0x1

    @api_call('ReadProcessMemory', argc=5)
    def ReadProcessMemory(self, proc, argv, ctx={}):
        '''
        BOOL ReadProcessMemory(
            HANDLE  hProcess,
            LPCVOID lpBaseAddress,
            LPVOID  lpBuffer,
            SIZE_T  nSize,
            SIZE_T  *lpNumberOfBytesRead
        );
        '''
        proc_handle, base_addr, pBuf, size, pRead_sz = argv
        targ_proc_obj = ObjectManager.get_obj_by_handle(proc_handle)
        mem_raw = targ_proc_obj.read_mem_self(base_addr, size)
        proc.write_mem_self(pBuf, mem_raw)
        proc.write_mem_self(pRead_sz, len(mem_raw).to_bytes(4, "little"))

        return True

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
            cmd = proc.read_string(lpCmdLine, 1)
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

        proc.write_mem_self(lpSystemTimeAsFileTime, ft.get_bytes())

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

        proc.write_mem_self(lpPerformanceCount, self.perf_counter.to_bytes(8, 'little'))
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
        tempdir = common.get_env(self.win_emu).get('temp', 'C:\\Windows\\temp\\')
        if cw == 2:
            new = (tempdir).encode('utf-16le') + b'\x00\x00'
        else:
            new = (tempdir).encode('utf-8') + b'\x00'
        rv = len(tempdir)
        if lpBuffer:
            argv[1] = tempdir
            proc.write_mem_self(lpBuffer, new)
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

        heap_obj = self.win_emu.mem_manager.create_heap(proc.pid, dwInitialSize, dwMaximumSize)
        handle = heap_obj.get_handle()
        return handle

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
        heap = self.win_emu.obj_manager.get_obj_by_handle(hHeap)
        if heap:
            return win_const.NULL
        pMem = self.win_emu.mem_manager.alloc_heap(heap, dwBytes)
        
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
        self.win_emu.mem_manager.free_heap(hHeap, lpMem)
        
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
        self.win_emu.mem_manager.destroy_heap(hHeap)

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

        pMem = self.win_emu.mem_manager.alloc_heap(proc.proc_default_heap, size)
        hnd = ObjectManager.create_new_object('EmLMEM', pMem, size, flag)
        if flag and 0x0: # LMEM_FIXED
            lMem_obj = ObjectManager.get_obj_by_handle(hnd)
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
        lMem_obj = ObjectManager.get_obj_by_handle(lmem_handle)
        return lMem_obj.base
    

    @api_call('LocalFlags', argc=1)
    def LocalFlags(self, proc, argv, ctx={}):
        '''
        UINT LocalFlags(
            HLOCAL hMem
        );
        '''
        lmem_handle, = argv
        lMem_obj = ObjectManager.get_obj_by_handle(lmem_handle)
        
        return lMem_obj.flags
    
    @api_call('LocalSize', argc=1)
    def LocalSize(self, proc, argv, ctx={}):
        '''
        SIZE_T LocalSize(
            HLOCAL hMem
        );
        '''
        lmem_handle, = argv
        lMem_obj = ObjectManager.get_obj_by_handle(lmem_handle)
        
        return lMem_obj.size

    @api_call('LocalFree', argc=1)
    def LocalFree(self, proc, argv, ctx={}):
        '''
        HLOCAL LocalFree(
            _Frees_ptr_opt_ HLOCAL hMem
        );
        '''
        lmem_handle, = argv
        lMem_obj = ObjectManager.get_obj_by_handle(lmem_handle)
        self.win_emu.mem_manager.free_heap(proc.proc_default_heap, lMem_obj.base)

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
            appstr = proc.read_string(app, cw)
            argv[0] = appstr
        if cmd:
            cmdstr = proc.read_string(cmd, cw)
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
        
        new_proc_obj, hProc, hThread = self.win_emu.create_process(appstr)
        main_thread = ObjectManager.get_obj_by_handle(hThread)
        EmuProcManager.push_wait_queue(new_proc_obj.pid, new_proc_obj)

        _pi = self.k32types.PROCESS_INFORMATION(proc.ptr_size)
        data = common.mem_cast(proc.uc_eng, _pi, ppi)
        _pi.hProcess = hProc
        _pi.hThread = hThread
        _pi.dwProcessId = new_proc_obj.pid
        _pi.dwThreadId = main_thread.tid

        proc.write_mem_self(ppi, common.get_bytes(data))

        rv = 1

        return rv

    @api_call('ExitProcess', argc=1)
    def ExitProcess(self, proc, argv, ctx={}):
        '''
        void ExitProcess(
            UINT uExitCode
        );
        '''
        self.win_emu_suspend_flag = True
        return

    @api_call('Sleep', argc=1)
    def Sleep(self, proc, argv, ctx={}):
        from time import sleep
        mills, = argv
        sleep(int(mills/1000))

        return