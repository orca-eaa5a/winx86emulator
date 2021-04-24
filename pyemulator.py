
import os
import pickle
import sys
import importlib
from time import sleep    
from fs.memoryfs import MemoryFS
from threading import Thread
import pefile
import struct
from unicorn.unicorn import UC_HOOK_MEM_ACCESS_CB, Uc, UcContext
from unicorn.unicorn_const import UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_HOOK_MEM_UNMAPPED, UC_MODE_32, UC_MODE_64
from pymanager import fs_manager, mem_manager, net_manager, obj_manager
from pymanager.defs import mem_defs, file_defs, net_defs
import pydll
import pygdt
import cb_handler
import speakeasy_origin.windef.nt.ntoskrnl as ntos

from speakeasy_origin.windef.windows.windows import CONTEXT
import speakeasy_origin.windef.windows.windows as wnd
from unicorn.x86_const import *
from pymanager.defs.mem_defs import PAGE_SIZE, ALLOCATION_GRANULARITY, PAGE_ALLOCATION_TYPE, PAGE_PROTECT, HEAP_OPTION, PAGE_TYPE

from keystone import * # using keystone as assembler
from capstone import * # using capstone as disassembler

class PyThread(Thread):
    def __init__(self, emu, thread):
        Thread.__init__(self)
        self.emu = emu
        self.thread = thread

    def run(self):
        self.emu.cur_thread = self.thread
        
        self.emu.set_emu_context(self.thread.ctx)
        self.thread.setup_ldt()
        
        cb_handler.ApiHandler.set_func_args(
                self.emu, 
                self.thread.ctx.Esp, 
                0, 
                self.thread.param
            )
        
        self.emu.running = True
        self.emu.cur_thread = self.thread
        self.emu.uc_eng.emu_start(self.thread.thread_entry, 0)

        pass

class WinX86Emu:
    pid = 0x7777

    @staticmethod
    def launch_thread(emu, t_obj:obj_manager.Thread, bk=0):
        pt = PyThread(emu, t_obj)
        pt.start()
        # pt.join()
        pass

    def __init__(self, fs_manager, net_manager, obj_manager):
        self.arch = UC_ARCH_X86
        self.mode = UC_MODE_32
        self.uc_eng = Uc(UC_ARCH_X86, UC_MODE_32)
        self.fs_manager = fs_manager
        self.mem_manager = mem_manager.MemoryManager(self.uc_eng)
        self.net_manager = net_manager
        self.obj_manager = obj_manager
        self._pe:pefile.PE = None
        self.entry_point = 0
        self.image_base = 0
        self.size_of_image = 0
        self.page_size = 0x1000
        self.peb_base = 0xcb000
        self.teb_base = 0xcb000+0x2000
        self.proc_default_heap = None
        self.peb_heap=None
        self.peb = None
        self.ldr_entries = []
        self.main_thread_handle = 0xFFFFFFFF
        self.cur_thread = None
        self.threads = []
        self.ctx:CONTEXT = None
        self.gdt = pygdt.GDT(self.uc_eng)
        self.mods = {}
        self.ptr_size = 0
        self.__set_emulation_config()
        self.api_handler = None
        self.code_cb_handler = None
        self.set_ptr_size()
        self.running = False
        self.hook_lst = []
        self.imp = {}
        # imp = {
        #   ...
        #   "dll_name": [("api_name", api_va), ... , ],
        #   ...
        # }
        # api_va_dict = {
        #   
        #   api_va : ("dll_name", "api_name") 
        #
        # }
        self.api_va_dict = {} # <-- Used in api call handling

        self.setup_api_handler()

    def __set_emulation_config(self, config=None):
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
        self.drive_config = config.get('drives', [])
        self.registry_config = config.get('registry', {})
        self.network_config = config.get('network', {})
        self.process_config = config.get('processes', [])
        self.command_line = config.get('command_line', '')
        self.img_name = config.get('image_name' '')
        self.img_path = config.get('image_path', '')

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

    def get_param(self):
        return self.command_line.split(" ")[1:]

    def default_heap_alloc(self, size):
        heap_seg = self.mem_manager.alloc_heap(self.proc_default_heap, size)

        return heap_seg
    
    def default_heap_free(self, pMem):
        self.mem_manager.free_heap(self.proc_default_heap, pMem)
        pass

    def setup_emu(self, pid, data):
        return self.create_process(pid, data)

    def launch(self):
        thread_obj = self.obj_manager.get_obj_by_handle(self.main_thread_handle)
        self.launch_thread(self, thread_obj)
        

        pass

    def quit_emu_sig(self):
        self.running = False

    def stop_emulation(self):
        self.uc_eng.emu_stop()

    def setup_api_handler(self):
        self.api_handler = cb_handler.ApiHandler(self)
        self.code_cb_handler = cb_handler.CodeCBHandler()
        
        h1 = self.uc_eng.hook_add(UC_HOOK_CODE, self.api_handler.api_call_cb_wrapper, (self, self.get_arch(), self.get_ptr_size()))
        #h2 = self.uc_eng.hook_add(UC_HOOK_CODE, self.code_cb_handler.logger, (self, self.get_arch(), self.get_ptr_size()))
        #h3 = self.uc_eng.hook_add(UC_HOOK_MEM_UNMAPPED, self.code_cb_handler.unmap_handler, (self, self.get_arch(), self.get_ptr_size()))
        self.hook_lst.append(h1)
        # self.hook_lst.append(h2)

        pass
    
    def __get_next_instruction(self, eip):
        _bin = self.uc_eng.mem_read(eip, 10)
        
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        for op in md.disasm(_bin, 0):
            return eip + op.size

    def __import_emulated_dll__(self, mod):
        def igetattr(obj, attr):
            for a in dir(obj):
                if a.lower() == attr.lower():
                    return getattr(obj, a)
            raise AttributeError

        if mod not in sys.modules:
            mod_obj = importlib.import_module("pydll." + mod)
            if mod not in self.mods:
                self.mods[mod] = igetattr(mod_obj, mod)(self)
        pass
    
    def create_process(self, pid, data:bytes):
        self.pid = pid
        self.__init_vas__()
        self.__load_exe__(data)
        self.__load_import_modules__()
        self.__make_imp_table__()
        self.__init_peb()
        self.main_thread_handle =  self.create_thread(self.entry_point, 0x10000)

        return self

    def get_context(self):
        ctx = CONTEXT(self.ptr_size)
        if self.ptr_size == UC_ARCH_X86:
            ctx.Eip = self.uc_eng.reg_read(UC_X86_REG_EIP)
            ctx.Ebp = self.uc_eng.reg_read(UC_X86_REG_EBP)
            ctx.Esp = self.uc_eng.reg_read(UC_X86_REG_ESP)
            ctx.Eax = self.uc_eng.reg_read(UC_X86_REG_EAX)
            ctx.Ebx = self.uc_eng.reg_read(UC_X86_REG_EBX)
            ctx.Ecx = self.uc_eng.reg_read(UC_X86_REG_ECX)
            ctx.Edx = self.uc_eng.reg_read(UC_X86_REG_EDX)
            ctx.Esi = self.uc_eng.reg_read(UC_X86_REG_ESI)
            ctx.Edi = self.uc_eng.reg_read(UC_X86_REG_EDI)
            ctx.Dr0 = self.uc_eng.reg_read(UC_X86_REG_DR0)
            ctx.Dr1 = self.uc_eng.reg_read(UC_X86_REG_DR1)
            ctx.Dr2 = self.uc_eng.reg_read(UC_X86_REG_DR2)
            ctx.Dr3 = self.uc_eng.reg_read(UC_X86_REG_DR3)
            ctx.Dr4 = self.uc_eng.reg_read(UC_X86_REG_DR4)
            ctx.Dr5 = self.uc_eng.reg_read(UC_X86_REG_DR5)
            ctx.Dr6 = self.uc_eng.reg_read(UC_X86_REG_DR6)
            ctx.Dr7 = self.uc_eng.reg_read(UC_X86_REG_DR7)
        else:
            raise Exception("Unsupported architecture")
        return ctx

    def set_emu_context(self, ctx):
        self.ctx = ctx
        if self.arch == UC_ARCH_X86:
            self.uc_eng.reg_write(UC_X86_REG_ESP, ctx.Esp)
            self.uc_eng.reg_write(UC_X86_REG_EBP, ctx.Ebp)
            self.uc_eng.reg_write(UC_X86_REG_EAX, ctx.Eax)
            self.uc_eng.reg_write(UC_X86_REG_EBX, ctx.Ebx)
            self.uc_eng.reg_write(UC_X86_REG_ECX, ctx.Ecx)
            self.uc_eng.reg_write(UC_X86_REG_EDX, ctx.Edx)
            self.uc_eng.reg_write(UC_X86_REG_ESI, ctx.Esi)
            self.uc_eng.reg_write(UC_X86_REG_EDI, ctx.Edi)
            self.uc_eng.reg_write(UC_X86_REG_DR0, ctx.Dr0)
            self.uc_eng.reg_write(UC_X86_REG_DR1, ctx.Dr1)
            self.uc_eng.reg_write(UC_X86_REG_DR2, ctx.Dr2)
            self.uc_eng.reg_write(UC_X86_REG_DR3, ctx.Dr3)
            self.uc_eng.reg_write(UC_X86_REG_DR4, ctx.Dr4)
            self.uc_eng.reg_write(UC_X86_REG_DR5, ctx.Dr5)
            self.uc_eng.reg_write(UC_X86_REG_DR6, ctx.Dr6)
            self.uc_eng.reg_write(UC_X86_REG_DR7, ctx.Dr7)

        else:
            raise Exception("Unsupported architecture")
        return ctx

    def switch_thread_context(self, t_obj:obj_manager.Thread, ret=0):
        
        origin_thread = self.cur_thread
        saved_ctx = self.uc_eng.context_save()
        #origin_context = self.get_context() <-- if change the ESP and EBP,
        #                                        unicorn engine is crashed
        
        cb_handler.ApiHandler.set_func_args(
                self, 
                t_obj.ctx.Esp, 
                0, 
                t_obj.param
            )
        self.uc_eng.emu_start(t_obj.thread_entry, 0)
        #saved_ctx = pickle.loads(pickled_ctx)
        self.cur_thread = origin_thread
        self.cur_thread.setup_ldt()
        self.uc_eng.context_restore(saved_ctx)
        self.uc_eng.context_update(saved_ctx)
        pass

    def create_thread(self, entry, stack_size, param=None, creation=wnd.CREATE_NEW):
        thread_stack_region = self.mem_manager.alloc_page(stack_size, PAGE_ALLOCATION_TYPE.MEM_COMMIT)
        stack_limit, stack_base = thread_stack_region.get_page_region_range()
        thread_handle = self.obj_manager.create_new_object(obj_manager.Thread, self, entry, stack_base-0x1000 , stack_limit, param)
        thread_obj:obj_manager.Thread = self.obj_manager.get_obj_by_handle(thread_handle)
        thread_obj.set_thread_stack(thread_stack_region)
        thread_obj.teb_heap = self.mem_manager.create_heap(0x10000, 0x10000)
        if creation & wnd.CREATE_SUSPENDED:
            thread_obj.suspend_count += 1
        teb_heap = self.mem_manager.alloc_heap(thread_obj.teb_heap, ntos.TEB(self.ptr_size).sizeof())

        gdt_page = self.mem_manager.alloc_page(0x1000, PAGE_ALLOCATION_TYPE.MEM_COMMIT)
        selectors = self.gdt.setup_selector(gdt_addr=gdt_page.get_base_addr(), fs_base=teb_heap, fs_limit=mem_defs.ALLOCATION_GRANULARITY)
        thread_obj.set_selectors(selectors)
        thread_obj.init_teb(self.peb_base)
        thread_obj.init_context()
        self.uc_eng.mem_write(teb_heap, thread_obj.teb.get_bytes())
        self.threads.append((thread_handle, thread_obj))

        return thread_handle

    def __init_vas__(self):
        unused = self.mem_manager.alloc_page(alloc_base=0,size=0x10000, allocation_type=mem_defs.PAGE_ALLOCATION_TYPE.MEM_RESERVE)
        thread_stack_size = 0x10000
        stack_base = self.mem_manager.alloc_page(alloc_base=0,size=thread_stack_size, allocation_type=mem_defs.PAGE_ALLOCATION_TYPE.MEM_COMMIT)
        self.peb_heap = self.mem_manager.create_heap(0x2000, 0)
        self.peb_base = self.mem_manager.alloc_heap(self.peb_heap, ntos.PEB(self.ptr_size).sizeof())
        

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
            dll_name = cb_handler.ApiHandler.api_set_schema(dll_name)
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

    def add_module_to_peb(self, dll:str):
        
        def __set_unicode_string(self, ustr, pystr:str):
            uBytes = (pystr+"\x00").encode("utf-16le")
            pMem = self.default_heap_alloc(len(uBytes)+1)
            ustr.Length = len(uBytes)
            ustr.MaximumLength = len(uBytes)+1
            ustr.Buffer = pMem

            self.uc_eng.mem_write(pMem, uBytes)

            pass

        new_ldte = ntos.LDR_DATA_TABLE_ENTRY(self.ptr_size)
        new_ldte.DllBase = pydll.SYSTEM_DLL_BASE[dll]
        new_ldte.Length = ntos.LDR_DATA_TABLE_ENTRY(self.ptr_size).sizeof()

        __set_unicode_string(self, new_ldte.BaseDllName, dll)
        __set_unicode_string(self, new_ldte.FullDllName, "C:\\Windows\\System32\\" + dll + ".dll")
        
        pNew_ldte = self.mem_manager.alloc_heap(self.peb_heap, new_ldte.sizeof())
        list_type = ntos.LIST_ENTRY(self.ptr_size)
        _first_link = False
        
        # Link created list_entry to LDR_MODULE
        if not self.ldr_entries:
            # first link
            _first_link = True
            
            pEntry, prev = self.peb.Ldr, self.peb_ldr_data
            
            prev.InLoadOrderModuleList.Flink = pNew_ldte
            prev.InMemoryOrderModuleList.Flink = pNew_ldte + list_type.sizeof()
            prev.InInitializationOrderModuleList.Flink = 0

        else:
            pEntry, prev = self.ldr_entries[-1]

            prev.InLoadOrderLinks.Flink = pNew_ldte
            prev.InMemoryOrderLinks.Flink = pNew_ldte + list_type.sizeof()
            prev.InInitializationOrderLinks.Flink = 0
        # Not implement Blink

        new_ldte.InLoadOrderLinks.Flink = self.peb.Ldr + 0xC
        new_ldte.InMemoryOrderLinks.Flink = self.peb.Ldr + 0xC + list_type.sizeof()
        
        self.ldr_entries.append((pNew_ldte, new_ldte))

        self.uc_eng.mem_write(pNew_ldte, new_ldte.get_bytes())
        self.uc_eng.mem_write(pEntry, prev.get_bytes())
        self.uc_eng.mem_write(self.peb_base, self.peb.get_bytes())
        self.uc_eng.mem_write(self.peb.Ldr, self.peb_ldr_data.get_bytes())

    def __init_peb(self):
        # Add an entry for each module in the module list
        self.peb = ntos.PEB(self.ptr_size)
        self.peb.ImageBaseAddress = self.image_base
        self.peb.ProcessHeap = self.proc_default_heap.get_base_addr()
        self.peb.Ldr = self.mem_manager.alloc_heap(self.peb_heap, ntos.PEB_LDR_DATA(self.ptr_size).sizeof())
        
        self.uc_eng.mem_write(
                self.mem_manager.alloc_heap(self.peb_heap, self.peb.sizeof()), 
                self.peb.get_bytes()
            )

        self.peb_ldr_data = ntos.PEB_LDR_DATA(self.ptr_size)

        for dll in self.imp:
            if dll not in pydll.SYSTEM_DLL_BASE:
                dll = cb_handler.ApiHandler.api_set_schema(dll)
            self.add_module_to_peb(dll)

    def __init_ldr__(self):
        
        if not self.imp:
            pass
        
        peb_ldr = ntos.PEB_LDR_DATA(self.ptr_size)
        peb_ldr_heap = self.peb_heap.allocate_heap_segment(peb_ldr.sizeof())
        self.peb.Ldr = peb_ldr_heap
        prev_link = peb_ldr
        prev_link_addr = peb_ldr_heap + 0xC
        
        for dll in self.imp:
            if dll not in pydll.SYSTEM_DLL_BASE:
                dll = cb_handler.ApiHandler.api_set_schema(dll)
            dll_base = pydll.SYSTEM_DLL_BASE[dll]
            new_module_link = ntos.LDR_DATA_TABLE_ENTRY(self.ptr_size)
            new_module_link_heap = self.peb_heap.allocate_heap_segment(new_module_link.sizeof())
            if isinstance(prev_link, ntos.LDR_DATA_TABLE_ENTRY):
                __set_unicode_string(self, new_module_link.BaseDllName, dll)
                __set_unicode_string(self, new_module_link.FullDllName, "C:\\Windows\\System32\\" + dll + ".dll")
                new_module_link.DllBase = self.image_base
                new_module_link.Length = new_module_link.sizeof()

                prev_link.InLoadOrderLinks.Flink = new_module_link_heap
                prev_link.InMemoryOrderLinks.Flink = new_module_link_heap + 8 # sizeof list entry
                prev_link.InInitializationOrderLinks.Flink = 0xFFFFFFFF # Not Implement in cur emulation

            else:
                
                __set_unicode_string(self, new_module_link.BaseDllName, self.img_name) 
                __set_unicode_string(self, new_module_link.FullDllName, self.img_path)
                new_module_link.DllBase = dll_base
                new_module_link.Length = new_module_link.sizeof()

                prev_link.InLoadOrderModuleList.Flink = new_module_link_heap
                prev_link.InMemoryOrderModuleList.Flink = new_module_link_heap + 8 # sizeof list entry
                prev_link.InInitializationOrderModuleList.Flink = 0xFFFFFFFF # Not Implement in cur emulation


            new_module_link.InLoadOrderLinks.Blink = prev_link_addr
            new_module_link.InMemoryOrderLinks.Blink = prev_link_addr + 8 # sizeof list entry
            new_module_link.InInitializationOrderLinks.Blink = 0xFFFFFFFF # Not Implement in cur emulation
            
            new_module_link.InLoadOrderLinks.Flink = self.peb.Ldr
            new_module_link.InMemoryOrderLinks.Flink = self.peb.Ldr + 8 # sizeof list entry
            new_module_link.InInitializationOrderLinks.Flink = 0xFFFFFFFF

            self.uc_eng.mem_write(prev_link_addr, prev_link.get_bytes())
            self.uc_eng.mem_write(new_module_link_heap, new_module_link.get_bytes())

            prev_link = new_module_link
            prev_link_addr = new_module_link_heap

        self.uc_eng.mem_write(self.peb_base, self.peb.get_bytes())