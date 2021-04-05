
import os
from fs.memoryfs import MemoryFS
from unicorn.unicorn import Uc
from unicorn.unicorn_const import UC_ARCH_X86, UC_MODE_32
import pefile
import struct
from pymanager import fs_manager, mem_manager, net_manager
from windef import *
import pydll
import pygdt

class WinX86Emu:
    def __init__(self, fs:MemoryFS):
        self.uc_eng = Uc(UC_ARCH_X86, UC_MODE_32)
        self.fs_manager = fs_manager.FileIOManager(fs)
        self.mem_manager = mem_manager.MemoryManager(self.uc_eng)
        self.net_manager = net_manager.NetworkManager()

        self.emu_os_v = {
            "name": "windows",
            "major": 6,
            "minor": 1,
            "build": 7777
        }
        self._pe:pefile.PE = None
        self.entry_point = 0
        self.image_base = 0
        self.size_of_image = 0
        self.page_size = 0x1000
        self.peb_base = 0xcb000
        self.teb_base = 0xcb000+0x2000
        self.proc_default_heap = None
        self.peb_heap=None
        self.teb_heap=None
        self.gdt = pygdt.GDT(self.uc_eng)
        self.mods = {}
        self.import_emulated_dll()
        self.ptr_size = 4 #x86
        self._parse_config()

        # imp = {
        #   ...
        #   "dll_name": [("api_name", api_va), ... , ],
        #   ...
        # }
        self.imp = {}
        # api_va_dict = {
        #   
        #   api_va : ("dll_name", "api_name") 
        #
        # }
        self.api_va_dict = {} # <-- Used in api call handling

    def get_argv(self):
        """
        Get command line arguments (if any) that are being passed
        to the emulated process. (e.g. main(argv))
        """
        argv0 = ''
        out = []

        return out

    def _parse_config(self, config=None):
        """
        Parse the config to be used for emulation
        """
        import json
        import jsonschema
        import jsonschema.exceptions

        if not config:
            config_path = os.path.join(os.getcwd(), "env.config")
            with open(config_path, 'r') as f:
                self.config = json.load(f)
        else:
            self.config = config

        if isinstance(config, str):
            config = json.loads(config)
        self.config = config

        self.osversion = config.get('os_ver', {})
        self.env = config.get('env', {})
        self.user_config = config.get('user', {})
        self.domain = config.get('domain')
        self.hostname = config.get('hostname')
        self.symlinks = config.get('symlinks', [])
        self.config_modules = config.get('modules', {})
        self.config_system_modules = self.config_modules.get('system_modules', [])
        self.config_processes = config.get('processes', [])
        self.config_user_modules = self.config_modules.get('user_modules', [])

        self.config_analysis = config.get('analysis', {})
        self.max_instructions = config.get('max_instructions', -1)
        self.timeout = config.get('timeout', 0)
        self.max_api_count = config.get('max_api_count', 5000)
        self.exceptions = config.get('exceptions', {})
        self.drive_config = config.get('drives', [])
        self.filesystem_config = config.get('filesystem', {})
        self.keep_memory_on_free = config.get('keep_memory_on_free', False)

        self.network_config = config.get('network', {})
        self.command_line = config.get('command_line', '')

    def default_heap_alloc(self, size):
        heap_seg = self.mem_manager.alloc_heap(self.proc_default_heap, size)

        return heap_seg
    
    def default_heap_free(self, pMem):
        self.mem_manager.free_heap(self.proc_default_heap, pMem)
        pass

    def import_emulated_dll(self):
        for mod in pydll.EMULATED_DLL_LIST:
            mod_obj = __import__(mod)
            # ("kernel32", pydll.kernel32.Kernel32)
            self.mods[mod] = mod_obj

    def init_vas(self):
        unused = self.mem_manager.alloc_page(alloc_base=0,size=0x10000, allocation_type=mem_defs.PAGE_ALLOCATION_TYPE.MEM_RESERVE)
        self.peb_heap = self.mem_manager.create_heap(0x2000, 0)
        self.peb_base = self.peb_heap.base_address
        self.teb_heap = self.mem_manager.create_heap(0x1000, 0x1000)
        self.teb_base = self.teb_heap.base_address
        self.gdt.setup(fs_base=self.teb_base, fs_limit=mem_defs.ALLOCATION_GRANULARITY)

    def load_exe(self, data):
        pe_bin = b''
        if isinstance(data, bytes) or isinstance(data, bytearray):
            pe_bin = bytes(data)
        elif isinstance(data, str):
            handle = self.fs_manager.create_file(data)
            pe_bin = self.fs_manager.read_file(handle.handle_id)
            self.fs_manager.close_file(handle.handle_id)

        else:
            raise Exception("Invalid request")

        self._pe = pefile.PE(data=pe_bin)
        if self._pe.DOS_HEADER.e_magic != struct.unpack("<H", b'MZ')[0]: # pylint: disable=no-member
            raise Exception("Target file is not PE")

        self.image_base = self._pe.OPTIONAL_HEADER.ImageBase
        self.size_of_image = self._pe.OPTIONAL_HEADER.SizeOfImage
        
        self.image_base = self.mem_manager.alloc_page(
                size=self.size_of_image, 
                allocation_type=mem_defs.PAGE_ALLOCATION_TYPE.MEM_RESERVE|mem_defs.PAGE_ALLOCATION_TYPE.MEM_RESERVE, 
                alloc_base=self.image_base, 
                protect=mem_defs.PAGE_PROTECT.PAGE_EXECUTE_READWRITE, 
                page_type=mem_defs.PAGE_TYPE.MEM_IMAGE
            )
        
        self.proc_default_heap = self.mem_manager.create_heap(1024*1024, 1024*1024)

        pe_image = self._pe.get_memory_mapped_image(ImageBase=self.image_base)
        self.uc_eng.mem_write(self.image_base, pe_image)
        del pe_image

    def update_api_va_dict(self, va, dll:str, api:str):
        self.api_va_dict[va] = (dll, api)
        pass

    def make_imp_table(self):
        # imp = {
        #   "dll": "Kernel32",
        #   "base": 0x1234,
        #   "imp": [("name", ordi), (....)]
        # }
        def rewrite_iat_table(uc, first_thunk_etry, addr):
            uc.mem_write(first_thunk_etry, addr)

        for dll in self._pe.DIRECTORY_ENTRY_IMPORT: # pylint: disable=no-member
            dll_name = dll.dll.decode("ascii")
            api_name = imp_api.name.decode("ascii")
            self.imp[dll_name] = []
            dll_base = pydll.SYSTEM_DLL_BASE[dll_name]
            for imp_api in dll.imports:
                self.imp[dll_name].append((api_name, dll_base + imp_api.hint))
                self.update_api_va_dict(dll_base + imp_api.hint, dll_name, api_name)
                rewrite_iat_table(self.uc_eng, imp_api.address, dll_base + imp_api.hint)
        pass
    
    def load_library(self, dll_name):
        if dll_name in pydll.SYSTEM_DLL_BASE.keys():
            if dll_name not in self.imp.keys():
                _sys_dll_init_base = pydll.SYSTEM_DLL_BASE[dll_name]
                alloc_base = self.mem_manager.alloc_page(
                        size=mem_defs.ALLOCATION_GRANULARITY, 
                        allocation_type=mem_defs.PAGE_ALLOCATION_TYPE.MEM_COMMIT | mem_defs.PAGE_ALLOCATION_TYPE.MEM_RESERVE, 
                        alloc_base=_sys_dll_init_base,
                        page_type=mem_defs.PAGE_TYPE.MEM_IMAGE
                    )
                pydll.SYSTEM_DLL_BASE[dll_name] = alloc_base
            # Fake load
            # overwrite RET at entire dll memory region
            self.uc_eng.mem_write(alloc_base, b'\xC3'*mem_defs.ALLOCATION_GRANULARITY)
            
            return pydll.SYSTEM_DLL_BASE[dll_name]
        else:
            return 0xFFFFFFFF # Invalid Handle

    def load_import_dll(self):
        for emu_dll in pydll.EMULATED_DLL_LIST:
            _sys_dll_init_base = pydll.SYSTEM_DLL_BASE[emu_dll]
            alloc_base = self.mem_manager.alloc_page(
                size=mem_defs.ALLOCATION_GRANULARITY, 
                    allocation_type=mem_defs.PAGE_ALLOCATION_TYPE.MEM_COMMIT | mem_defs.PAGE_ALLOCATION_TYPE.MEM_RESERVE, 
                    alloc_base=_sys_dll_init_base,
                    page_type=mem_defs.PAGE_TYPE.MEM_IMAGE)
            pydll.SYSTEM_DLL_BASE[emu_dll] = alloc_base

            
            self.uc_eng.mem_write(alloc_base, b'\xC3'*mem_defs.ALLOCATION_GRANULARITY)