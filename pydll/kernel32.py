# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# orca-eaa5a Edit
import os
import pydll

import speakeasy.winenv.defs.windows.windows as windefs
import speakeasy.winenv.defs.windows.kernel32 
from cb_handler import ApiHandler
from cb_handler import CALL_CONV as cv
import common
import speakeasy.winenv.defs.windows.kernel32 as k32types

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
    def GetTickCount(self, emu, argv, ctx={}):
        '''
        DWORD GetTickCount();
        '''

        self.tick_counter += 20

        return self.tick_counter

    """
    @api_call('CreateToolhelp32Snapshot', argc=2)
    def CreateToolhelp32Snapshot(self, emu, argv, ctx={}):
        '''
        HANDLE CreateToolhelp32Snapshot(
            DWORD dwFlags,
            DWORD th32ProcessID
        );
        '''

        dwFlags, th32ProcessID, = argv

        if k32types.TH32CS_SNAPPROCESS == dwFlags:
            hnd = self.get_handle()
            index = 0
            self.snapshots.update({hnd: [index, emu.get_processes()]})
        elif k32types.TH32CS_SNAPTHREAD == dwFlags:
            hnd = self.get_handle()
            index = 0
            if th32ProcessID in [0, emu.curr_process.get_pid()]:
                proc = emu.curr_process
            else:
                for p in emu.get_processes():
                    if th32ProcessID == p.get_pid():
                        proc = p
                        break
                else:
                    raise ApiEmuError('The specified PID not found')
            self.snapshots.update({hnd: [index, proc.threads, proc.get_pid()]})
        else:
            raise ApiEmuError('Unsupported snapshot type: 0x%x' % (dwFlags))

        cap_def = k32types.get_flag_defines(dwFlags, 'TH32CS')
        if cap_def:
            cap_def = '|'.join(cap_def)
            argv[0] = cap_def

        return hnd
    @api_call('Process32First', argc=2)
    def Process32First(self, emu, argv, ctx={}):
        '''
        BOOL Process32First(
            HANDLE           hSnapshot,
            LPPROCESSENTRY32 lppe
        );
        '''

        hSnapshot, pe32, = argv
        rv = False

        snap = self.snapshots.get(hSnapshot)
        if not snap or not pe32:
            return rv

        # Reset the handle index
        snap[0] = 1
        proc = snap[1][0]

        try:
            cw = self.get_char_width(ctx)
        except Exception:
            cw = 1

        pe = self.k32types.PROCESSENTRY32(emu.get_ptr_size(), cw)
        data = self.mem_cast(pe, pe32)
        pe.th32ProcessID = proc.get_pid()
        if cw == 2:
            pe.szExeFile = proc.image.encode('utf-16le') + b'\x00'
        else:
            pe.szExeFile = proc.image.encode('utf-8') + b'\x00'

        self.mem_write(pe32, self.get_bytes(data))
        rv = True
        return rv

    @api_call('Process32Next', argc=2)
    def Process32Next(self, emu, argv, ctx={}):
        '''
        BOOL Process32Next(
            HANDLE           hSnapshot,
            LPPROCESSENTRY32 lppe
        );
        '''

        hSnapshot, pe32, = argv
        rv = False

        snap = self.snapshots.get(hSnapshot)
        if not snap or not pe32:
            return rv

        index = snap[0]
        snap[0] += 1
        if index >= len(snap[1]):
            return rv
        proc = snap[1][index]

        try:
            cw = self.get_char_width(ctx)
        except Exception:
            cw = 1

        pe = self.k32types.PROCESSENTRY32(emu.get_ptr_size(), cw)
        data = self.mem_cast(pe, pe32)
        pe.th32ProcessID = proc.get_pid()
        if cw == 2:
            pe.szExeFile = proc.image.encode('utf-16le') + b'\x00'
        else:
            pe.szExeFile = proc.image.encode('utf-8') + b'\x00'

        self.mem_write(pe32, self.get_bytes(data))
        rv = True
        return rv

    @api_call('Thread32First', argc=2)
    def Thread32First(self, emu, argv, ctx={}):
        '''
        BOOL Thread32First(
        HANDLE          hSnapshot,
        LPTHREADENTRY32 lpte
        );
        '''

        hSnapshot, te32, = argv
        rv = False

        snap = self.snapshots.get(hSnapshot)
        if not snap or not te32:
            return rv

        # Reset the handle index
        snap[0] = 1
        thread = snap[1][0]

        te = self.k32types.THREADENTRY32(emu.get_ptr_size())
        data = self.mem_cast(te, te32)
        te.th32ThreadID = thread.tid
        te.th32OwnerProcessID = snap[2]

        self.mem_write(te32, self.get_bytes(data))
        rv = True
        return rv

    @api_call('Thread32Next', argc=2)
    def Thread32Next(self, emu, argv, ctx={}):
        '''
        BOOL Thread32Next(
        HANDLE          hSnapshot,
        LPTHREADENTRY32 lpte
        );
        '''

        hSnapshot, te32, = argv
        rv = False

        snap = self.snapshots.get(hSnapshot)
        if not snap or not te32:
            return rv

        index = snap[0]
        snap[0] += 1
        if index >= len(snap[1]):
            return rv
        thread = snap[1][index]

        te = self.k32types.THREADENTRY32(emu.get_ptr_size())
        data = self.mem_cast(te, te32)
        te.th32ThreadID = thread.tid
        te.th32OwnerProcessID = snap[2]

        self.mem_write(te32, self.get_bytes(data))
        rv = True
        return rv

    @api_call('OpenProcess', argc=3)
    def OpenProcess(self, emu, argv, ctx={}):
        '''
        HANDLE OpenProcess(
            DWORD dwDesiredAccess,
            BOOL  bInheritHandle,
            DWORD dwProcessId
        );
        '''

        access, inherit, pid = argv

        hnd = 0
        proc = emu.get_object_from_id(pid)
        if proc:
            hnd = emu.get_object_handle(proc)
        else:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
        return hnd

    @api_call('OpenMutex', argc=3)
    def OpenMutex(self, emu, argv, ctx={}):
        '''
        HANDLE OpenMutex(
            DWORD   dwDesiredAccess,
            BOOL    bInheritHandle,
            LPCWSTR lpName
        );
        '''

        access, inherit, name = argv

        cw = self.get_char_width(ctx)

        if name:
            obj_name = self.read_mem_string(name, cw)
            argv[2] = obj_name

        obj = self.get_object_from_name(obj_name)

        hnd = 0
        if obj:
            hnd = emu.get_object_handle(obj)
        else:
            emu.set_last_error(windefs.ERROR_INVALID_PARAMETER)
        return hnd
        
    @api_call('CreateMutex', argc=3)
    def CreateMutex(self, emu, argv, ctx={}):
        # implement after implement obj manager
        '''
        HANDLE CreateMutex(
            LPSECURITY_ATTRIBUTES lpMutexAttributes,
            BOOL                  bInitialOwner,
            LPCSTR                lpName
        );
        '''

        attrs, owner, name = argv

        cw = self.get_char_width(ctx)

        if name:
            name = self.read_mem_string(name, cw)

        obj = self.get_object_from_name(name)

        hnd = 0
        if obj:
            hnd = emu.get_object_handle(obj)
            emu.set_last_error(windefs.ERROR_ALREADY_EXISTS)
        else:
            emu.set_last_error(windefs.ERROR_SUCCESS)
            hnd, evt = emu.create_mutant(name)

        argv[2] = name
        return hnd

    @api_call('CreateMutexEx', argc=4)
    def CreateMutexEx(self, emu, argv, ctx={}):
        '''
        HANDLE CreateMutexExA(
          LPSECURITY_ATTRIBUTES lpMutexAttributes,
          LPCSTR                lpName,
          DWORD                 dwFlags,
          DWORD                 dwDesiredAccess
        );
        '''
        attrs, name, flags, access = argv

        cw = self.get_char_width(ctx)

        if name:
            name = self.read_mem_string(name, cw)

        obj = self.get_object_from_name(name)

        hnd = 0
        if obj:
            hnd = emu.get_object_handle(obj)
            emu.set_last_error(windefs.ERROR_ALREADY_EXISTS)
        else:
            emu.set_last_error(windefs.ERROR_SUCCESS)
            hnd, evt = emu.create_mutant(name)

        argv[1] = name
        return hnd
    """

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

    