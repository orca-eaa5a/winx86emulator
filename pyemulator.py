
import os
import sys
from fs.memoryfs import MemoryFS
from unicorn.unicorn import Uc
from unicorn.unicorn_const import UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_MODE_32, UC_MODE_64
import pefile
import struct
from pymanager import fs_manager, mem_manager, net_manager
from pymanager.defs import mem_defs, file_defs, net_defs
import pydll
import pygdt
import api_handler

from unicorn.x86_const import UC_X86_REG_ESP
from keystone import * # using keystone as assembler
from capstone import * # using capstone as disassembler

class WinX86Emu:
    def __init__(self, fs:MemoryFS):
        self.arch = UC_ARCH_X86
        self.mode = UC_MODE_32
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
        self.ptr_size = 4 #x86
        self._parse_config()
        self.api_handler = None
        self.ptr_size = 0
        self.set_ptr_size()
        self.setup_api_handler()
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

    def get_ptr_size(self):
        return self.ptr_size

    def get_arch(self):
        return self.arch

    def set_ptr_size(self):
        if self.arch == UC_ARCH_X86 and self.mode == UC_MODE_32:
            self.ptr_size = 4
        elif self.arch == UC_ARCH_X86 and self.mode == UC_MODE_64:
            self.ptr_size = 8
        else:
            raise Exception("Unsupported architecture")


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
                config = self.config
        else:
            self.config = config

        if isinstance(config, str):
            config = json.loads(config)
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

    def setup_emu(self, data):
        self.__init_vas__()
        self.__load_exe__(data)
        self.__load_import_modules__()
        self.__make_imp_table__()

    def invalid_fetch_handler(self, uc, access, addr, size, value, emu):
        print(hex(addr))
        sp = emu.uc_eng.reg_read(UC_X86_REG_ESP) # stack pointer
        oret = struct.unpack("<I", emu.uc_engmem_read(emu.uc_engreg_read(UC_X86_REG_ESP), 4))[0]
        args = struct.unpack('<IIIIII', emu.uc_eng.mem_read(sp, 24))
        
        CODE = emu.uc_eng.mem_read(addr, size)
        
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        for i in md.disasm(bytes(CODE), addr):
            print("%x:%s%s\t%s" %(i.address, 2 * '\t', i.mnemonic, i.op_str))

        for i in range(1, 5):
            strval = emu.uc_eng.mem_read(args[i], 30).decode('utf8', errors='ignore').strip('\x00')
            print('>>> args_%i(%x) --> %.8x | %s' % (i, sp + 4 * i, args[i], strval))
        print('---------------------------------------------------------\n')

    def launch(self):
        try:
            self.uc_eng.emu_start(self.entry_point, 0xFFFFFFFF)
        except Exception as e:
            print(e)
            raise Exception("Emulation error %s" % e)

        pass

    def setup_api_handler(self):
        self.api_handler = api_handler.ApiHandler(self)
        self.uc_eng.hook_add(UC_HOOK_CODE, self.api_handler.api_call_cb_wrapper, (self, self.get_arch(), self.get_ptr_size()))
        self.uc_eng.hook_add(UC_HOOK_MEM_INVALID, self.invalid_fetch_handler, self)

        pass

    def __import_emulated_dll__(self, mod):
        if mod not in sys.modules:
            mod_obj = __import__("pydll." + mod)
            if mod not in self.mods:
                self.mods[mod] = mod_obj
        pass

    def __init_vas__(self):
        unused = self.mem_manager.alloc_page(alloc_base=0,size=0x10000, allocation_type=mem_defs.PAGE_ALLOCATION_TYPE.MEM_RESERVE)
        self.peb_heap = self.mem_manager.create_heap(0x2000, 0)
        self.peb_base = self.peb_heap.get_base_addr()
        self.teb_heap = self.mem_manager.create_heap(0x1000, 0x1000)
        self.teb_base = self.teb_heap.get_base_addr()
        self.gdt.setup(fs_base=self.teb_base, fs_limit=mem_defs.ALLOCATION_GRANULARITY)

    def __load_exe__(self, data):
        pe_bin = b''
        if isinstance(data, bytes) or isinstance(data, bytearray):
            pe_bin = bytes(data)
        elif isinstance(data, str):
            data = os.path.split(data)[-1]
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
        self.entry_point = self.image_base + self._pe.OPTIONAL_HEADER.AddressOfEntryPoint
        
        image_pages = self.mem_manager.alloc_page(
                size=self.size_of_image, 
                allocation_type=mem_defs.PAGE_ALLOCATION_TYPE.MEM_RESERVE|mem_defs.PAGE_ALLOCATION_TYPE.MEM_RESERVE, 
                alloc_base=self.image_base, 
                protect=mem_defs.PAGE_PROTECT.PAGE_EXECUTE_READWRITE, 
                page_type=mem_defs.PAGE_TYPE.MEM_IMAGE
            )
        self.image_base = image_pages.get_base_addr()
        self.proc_default_heap = self.mem_manager.create_heap(1024*1024, 1024*1024)

        pe_image = self._pe.get_memory_mapped_image(ImageBase=self.image_base)
        self.uc_eng.mem_write(self.image_base, pe_image)
        del pe_image

    def __update_api_va_dict__(self, va, dll:str, api:str):
        self.api_va_dict[va] = (dll, api)
        pass

    def __make_imp_table__(self):
        # imp = {
        #   "dll": "Kernel32",
        #   "base": 0x1234,
        #   "imp": [("name", ordi), (....)]
        # }
        def __rewrite_iat_table__(uc, first_thunk_etry, addr):
            addr = struct.pack("I", addr)
            uc.mem_write(first_thunk_etry, addr)

        for dll in self._pe.DIRECTORY_ENTRY_IMPORT: # pylint: disable=no-member
            dll_name = dll.dll.decode("ascii").lower().split(".")[0]
            self.imp[dll_name] = []
            if dll_name not in pydll.SYSTEM_DLL_BASE:
                dll_name = self.api_handler.api_set_schema(dll_name)
            try:
                dll_base = pydll.SYSTEM_DLL_BASE[dll_name]
            except:
                raise Exception("Unsupported DLL")
            for imp_api in dll.imports:
                api_name = imp_api.name.decode("ascii")
                if dll_name not in self.imp:
                    self.imp[dll_name] = [(api_name, dll_base + imp_api.hint)]
                self.imp[dll_name].append((api_name, dll_base + imp_api.hint))
                self.__update_api_va_dict__(dll_base + imp_api.hint, dll_name, api_name)
                __rewrite_iat_table__(self.uc_eng, imp_api.address, dll_base + imp_api.hint)
        pass
    

    def load_library(self, dll_name):
        if dll_name not in pydll.SYSTEM_DLL_BASE:
            dll_name = api_handler.ApiHandler.api_set_schema(dll_name)
        if dll_name not in pydll.SYSTEM_DLL_BASE:
            return 0xFFFFFFFF # Invalid Handle
        
        if dll_name not in self.imp:
            _sys_dll_init_base = pydll.SYSTEM_DLL_BASE[dll_name]
            dll_page = self.mem_manager.alloc_page(
                    size=mem_defs.ALLOCATION_GRANULARITY, 
                    allocation_type=mem_defs.PAGE_ALLOCATION_TYPE.MEM_COMMIT | mem_defs.PAGE_ALLOCATION_TYPE.MEM_RESERVE, 
                    alloc_base=_sys_dll_init_base,
                    page_type=mem_defs.PAGE_TYPE.MEM_IMAGE
                )
            pydll.SYSTEM_DLL_BASE[dll_name] = dll_page.get_base_addr()
            self.__import_emulated_dll__(dll_name)
            # Fake load
            # overwrite RET at entire dll memory region
            self.uc_eng.mem_write(dll_page.get_base_addr(), b'\xC3'*mem_defs.ALLOCATION_GRANULARITY)
            
            return pydll.SYSTEM_DLL_BASE[dll_name]

        return 0xFFFFFFFF # Invalid Handle

    def __load_import_modules__(self):
        for emu_dll in pydll.EMULATED_DLL_LIST:
            self.load_library(emu_dll)