
import os
import pickle
import sys
import importlib
from fs.memoryfs import MemoryFS
from threading import Thread, stack_size
import pefile
import struct
from unicorn.unicorn import UC_HOOK_MEM_ACCESS_CB, Uc, UcContext
from unicorn.unicorn_const import UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_HOOK_MEM_UNMAPPED, UC_MODE_32, UC_MODE_64
from pymanager import fs_manager, mem_manager, net_manager, obj_manager
from pymanager.defs import mem_defs, file_defs, net_defs
import speakeasy_origin.windef.windows.windows as windef

import pydll
import pygdt
import cb_handler
import speakeasy_origin.windef.nt.ntoskrnl as ntos

from speakeasy_origin.windef.windows.windows import CONTEXT
from unicorn.x86_const import *
from pymanager.defs.mem_defs import PAGE_SIZE, ALLOCATION_GRANULARITY, PAGE_ALLOCATION_TYPE, PAGE_PROTECT, HEAP_OPTION, PAGE_TYPE

from keystone import * # using keystone as assembler
from capstone import * # using capstone as disassembler

class WinX86Emu:
    def __init__(self, vfs_manager, net_manager, obj_manager):
        self.arch = UC_ARCH_X86
        self.mode = UC_MODE_32
        self.fs_manager:fs_manager.FileIOManager = vfs_manager
        self.net_manager = net_manager
        self.obj_manager = obj_manager
        self.cur_thread = None
        self.threads = []
        self.ctx:CONTEXT = None
        self.ptr_size = 0
        self.api_handler = None
        self.code_cb_handler = None
        self.set_ptr_size()
        self.wait_proc_queue = []
        self.hook_lst = []
        self.winapi_info_dict = {}
        self.__set_emulation_config()
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
    def push_wait_queue(self, proc:obj_manager.EmProcess):
        self.wait_proc_queue.append(proc)
        pass

    def pop_wait_queue(self):
        return self.wait_proc_queue.pop()

    def init_vas(self, proc_obj:obj_manager.EmProcess):

        unused = proc_obj.vas_manager.alloc_page(alloc_base=0,size=0x10000, allocation_type=mem_defs.PAGE_ALLOCATION_TYPE.MEM_RESERVE)
        peb_heap = proc_obj.vas_manager.create_heap(0x2000, 0)
        peb_base = proc_obj.vas_manager.alloc_heap(peb_heap, ntos.PEB(self.ptr_size).sizeof())
        proc_default_heap = proc_obj.vas_manager.create_heap(1024*1024, 1024*1024)
        
        proc_obj.set_peb_heap(peb_heap)
        proc_obj.set_peb_base(peb_base)
        proc_obj.set_proc_default_heap(proc_default_heap)
        pass

    def load_target_proc(self, proc_obj:obj_manager.EmProcess):
        _pe_ = proc_obj.parsed_pe

        if _pe_.DOS_HEADER.e_magic != struct.unpack("<H", b'MZ')[0]: # pylint: disable=no-member
            raise Exception("Target file is not PE")

        image_base = _pe_.OPTIONAL_HEADER.ImageBase
        size_of_image = _pe_.OPTIONAL_HEADER.SizeOfImage
        ep = image_base + _pe_.OPTIONAL_HEADER.AddressOfEntryPoint
        image_pages = proc_obj.vas_manager.alloc_page(
                size=size_of_image, 
                allocation_type=mem_defs.PAGE_ALLOCATION_TYPE.MEM_RESERVE|mem_defs.PAGE_ALLOCATION_TYPE.MEM_RESERVE, 
                alloc_base=image_base, 
                protect=mem_defs.PAGE_PROTECT.PAGE_EXECUTE_READWRITE, 
                page_type=mem_defs.PAGE_TYPE.MEM_IMAGE
            )
        image_base = image_pages.get_base_addr()
        
        proc_obj.set_image_base(image_base)
        proc_obj.set_ep(ep)

        pe_image = _pe_.get_memory_mapped_image(ImageBase=image_base)
        proc_obj.uc_eng.mem_write(image_base, pe_image)
        
        del pe_image

    def load_import_mods(self, proc_obj:obj_manager.EmProcess):
        # will be changed
        # cur  : load all modules that was emulated
        # todo : load specific modules which recorded in IAT
        for dll_name in pydll.EMULATED_DLL_LIST:
            self.load_library(dll_name, proc_obj)

    def load_library(self, dll_name, proc_obj:obj_manager.EmProcess):
        if dll_name not in pydll.SYSTEM_DLL_BASE:
            dll_name = cb_handler.ApiHandler.api_set_schema(dll_name)
        if dll_name not in pydll.SYSTEM_DLL_BASE:
            return 0xFFFFFFFF # Invalid Handle
        
        if dll_name not in proc_obj.imports:
            _sys_dll_init_base = pydll.SYSTEM_DLL_BASE[dll_name]
            dll_page = proc_obj.vas_manager.alloc_page(
                    size=mem_defs.ALLOCATION_GRANULARITY, 
                    allocation_type=mem_defs.PAGE_ALLOCATION_TYPE.MEM_COMMIT | mem_defs.PAGE_ALLOCATION_TYPE.MEM_RESERVE, 
                    alloc_base=_sys_dll_init_base,
                    page_type=mem_defs.PAGE_TYPE.MEM_IMAGE
                )
            pydll.SYSTEM_DLL_BASE[dll_name] = dll_page.get_base_addr()
            self.setup_emulated_dllobj(dll_name, proc_obj)
            # Fake load
            # overwrite RET at entire dll memory region
            proc_obj.uc_eng.mem_write(dll_page.get_base_addr(), b'\xC3'*mem_defs.ALLOCATION_GRANULARITY)
            
            self.add_module_to_peb(proc_obj, dll_name)
            return pydll.SYSTEM_DLL_BASE[dll_name]

        return 0xFFFFFFFF # Invalid Handle

    def setup_emulated_dllobj(self, mod_name, proc_obj:obj_manager.EmProcess):
        def igetattr(obj, attr):
            for a in dir(obj):
                if a.lower() == attr.lower():
                    return getattr(obj, a)
            raise AttributeError

        if mod_name not in sys.modules:
            mod_obj = importlib.import_module("pydll." + mod_name)
            if mod_name not in proc_obj.e_dllobj:
                proc_obj.add_e_dll_obj(mod_name, igetattr(mod_obj, mod_name)(proc_obj))
        pass

    def setup_import_tab(self, proc_obj:obj_manager.EmProcess):
        def rewrite_iat_table(uc, first_thunk_etry, addr):
            addr = struct.pack("I", addr)
            uc.mem_write(first_thunk_etry, addr)

        for dll in proc_obj.parsed_pe.DIRECTORY_ENTRY_IMPORT: # pylint: disable=no-member
            dll_name = dll.dll.decode("ascii").lower().split(".")[0]
            proc_obj.set_imports(dll_name, [])
            if dll_name not in pydll.SYSTEM_DLL_BASE:
                dll_name = self.api_handler.api_set_schema(dll_name)
            try:
                dll_base = pydll.SYSTEM_DLL_BASE[dll_name]
            except:
                raise Exception("Unsupported DLL")
            for imp_api in dll.imports:
                api_name = imp_api.name.decode("ascii")
                if dll_name not in proc_obj.imports:
                    proc_obj.set_imports(dll_name, [(api_name, dll_base + imp_api.hint)])
                proc_obj.add_imports(dll_name, (api_name, dll_base + imp_api.hint))
                proc_obj.set_api_va_dict(dll_base + imp_api.hint, (dll_name, api_name))
                rewrite_iat_table(proc_obj.uc_eng, imp_api.address, dll_base + imp_api.hint)
        pass

    def init_peb(self, proc_obj:obj_manager.EmProcess):
        # Add an entry for each module in the module list
        peb = ntos.PEB(self.ptr_size)
        peb.ImageBaseAddress = proc_obj.image_base
        peb.ProcessHeap = proc_obj.proc_default_heap.get_base_addr()
        peb.Ldr = proc_obj.vas_manager.alloc_heap(proc_obj.peb_heap, ntos.PEB_LDR_DATA(self.ptr_size).sizeof())
        proc_obj.set_peb(peb)
        proc_obj.uc_eng.mem_write(
                proc_obj.vas_manager.alloc_heap(proc_obj.peb_heap, peb.sizeof()), 
                peb.get_bytes()
            )
        peb_ldr_data = ntos.PEB_LDR_DATA(self.ptr_size)
        proc_obj.set_peb_ldr(peb_ldr_data)
        proc_obj.uc_eng.mem_write(peb.Ldr, peb_ldr_data.get_bytes())

    def add_module_to_peb(self, proc_obj:obj_manager.EmProcess, mod_name:str):
        
        def set_unicode_string(proc_obj:obj_manager.EmProcess, ustr, pystr:str):
            uBytes = (pystr+"\x00").encode("utf-16le")
            pMem = proc_obj.vas_manager.alloc_heap(proc_obj.proc_default_heap, len(uBytes)+1)
            ustr.Length = len(uBytes)
            ustr.MaximumLength = len(uBytes)+1
            ustr.Buffer = pMem

            proc_obj.uc_eng.mem_write(pMem, uBytes)

            pass
        
        new_ldte = ntos.LDR_DATA_TABLE_ENTRY(self.ptr_size)
        new_ldte.DllBase = pydll.SYSTEM_DLL_BASE[mod_name]
        new_ldte.Length = ntos.LDR_DATA_TABLE_ENTRY(self.ptr_size).sizeof()

        set_unicode_string(proc_obj, new_ldte.BaseDllName, mod_name)
        set_unicode_string(proc_obj, new_ldte.FullDllName, "C:\\Windows\\System32\\" + mod_name + ".dll")
        
        pNew_ldte = proc_obj.vas_manager.alloc_heap(proc_obj.peb_heap, new_ldte.sizeof())
        list_type = ntos.LIST_ENTRY(self.ptr_size)
        
        # Link created list_entry to LDR_MODULE
        if not proc_obj.ldr_entries:
            
            pEntry, prev = proc_obj.peb.Ldr, proc_obj.peb_ldr_data
            
            prev.InLoadOrderModuleList.Flink = pNew_ldte
            prev.InMemoryOrderModuleList.Flink = pNew_ldte + list_type.sizeof()
            prev.InInitializationOrderModuleList.Flink = 0

        else:
            pEntry, prev = proc_obj.ldr_entries[-1]

            prev.InLoadOrderLinks.Flink = pNew_ldte
            prev.InMemoryOrderLinks.Flink = pNew_ldte + list_type.sizeof()
            prev.InInitializationOrderLinks.Flink = 0
        # Not implement Blink

        new_ldte.InLoadOrderLinks.Flink = proc_obj.peb.Ldr + 0xC
        new_ldte.InMemoryOrderLinks.Flink = proc_obj.peb.Ldr + 0xC + list_type.sizeof()
        
        proc_obj.add_ldr_entry((pNew_ldte, new_ldte))

        proc_obj.uc_eng.mem_write(pNew_ldte, new_ldte.get_bytes())
        proc_obj.uc_eng.mem_write(pEntry, prev.get_bytes())
        proc_obj.uc_eng.mem_write(proc_obj.peb_base, proc_obj.peb.get_bytes())
        proc_obj.uc_eng.mem_write(proc_obj.peb.Ldr, proc_obj.peb_ldr_data.get_bytes())
        
        pass

    def create_process(self, file_name):
        def parse_pe_binary(pe_bin):
            return pefile.PE(data=pe_bin)
        uc_eng = Uc(UC_ARCH_X86, UC_MODE_32)
        vas_manager = mem_manager.MemoryManager(uc_eng)

        proc_obj:obj_manager.EmProcess = obj_manager.EmProcess(uc_eng, self, vas_manager)
        proc_obj.set_gdt(pygdt.GDT(uc_eng))
        proc_obj.set_filename(file_name)
        f_handle = self.fs_manager.create_file(file_name)
        proc_obj.set_filehandle(f_handle)

        if f_handle == windef.INVALID_HANDLE_VALUE:
            raise Exception("There is no target file to execute")
        pe_bin = self.fs_manager.read_file(f_handle.handle_id)
        _pe_ = parse_pe_binary(pe_bin)
        proc_obj.set_parsed_pe(_pe_)

        self.init_vas(proc_obj)
        self.init_peb(proc_obj)
        self.load_target_proc(proc_obj)
        self.setup_api_handler(proc_obj)
        self.load_import_mods(proc_obj)
        self.setup_import_tab(proc_obj)
        self.create_thread(proc_obj, proc_obj.entry_point)

        return proc_obj

    def create_process_ex(self, section_handle):
        pass

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

    def setup_emu(self, data):
        proc_obj = self.create_process(data)
        self.push_wait_queue(proc_obj)
        return self

    def launch(self):
        while len(self.wait_proc_queue) != 0:
            proc_obj:obj_manager.EmProcess = self.pop_wait_queue()
            proc_obj.resume()
        pass

    def setup_api_handler(self, proc_obj:obj_manager.EmProcess):
        self.api_handler = cb_handler.ApiHandler(proc_obj)
        self.code_cb_handler = cb_handler.CodeCBHandler()
        
        h1 = proc_obj.uc_eng.hook_add(UC_HOOK_CODE, self.api_handler.pre_api_call_cb_wrapper, (proc_obj, self.get_arch(), self.get_ptr_size()))
        #h2 = proc_obj.uc_eng.hook_add(UC_HOOK_CODE, self.code_cb_handler.logger, (proc_obj, self.get_arch(), self.get_ptr_size()))
        #h3 = self.uc_eng.hook_add(UC_HOOK_MEM_UNMAPPED, self.code_cb_handler.unmap_handler, (self, self.get_arch(), self.get_ptr_size()))
        self.hook_lst.append(h1)
        #self.hook_lst.append(h2)

        pass

    def switch_thread_context(self, proc_obj:obj_manager.EmProcess, thread_obj:obj_manager.EmThread, ret=0):
        def context_switch_cb(proc_obj:obj_manager.EmProcess, thread_handle):
            proc_obj.running_thread.save_context()
            proc_obj.push_waiting_queue(proc_obj.running_thread.handle)
            proc_obj.push_waiting_queue(thread_handle)
            proc_obj.uc_eng.hook_del(proc_obj.ctx_switch_hook)
            proc_obj.running_thread.suspend_thread()
        proc_obj.ctx_switch_hook = proc_obj.uc_eng.hook_add(UC_HOOK_CODE, self.api_handler.post_api_call_cb_wrapper, (proc_obj, (proc_obj, thread_obj.handle), 1, context_switch_cb))
        pass

    def create_thread(
        self,
        proc_obj:obj_manager.EmProcess,
        thread_entry,
        param=None,
        stack_size=1024*1024, # 1MB default stack size
        creation=windef.CREATE_NEW
        ):
        stack_size = stack_size
        thread_stack_region = proc_obj.vas_manager.alloc_page(stack_size, PAGE_ALLOCATION_TYPE.MEM_COMMIT)
        stack_limit, stack_base = thread_stack_region.get_page_region_range()
        thread_handle = self.obj_manager.create_new_object(
                obj_manager.EmThread, proc_obj, 
                thread_entry, 
                stack_base-stack_size+0x1000, 
                stack_limit, 
                param
            )
        thread_obj:obj_manager.EmThread = self.obj_manager.get_obj_by_handle(thread_handle)
        thread_obj.handle = thread_handle
        thread_obj.set_thread_stack(thread_stack_region)
        thread_obj.teb_heap = proc_obj.vas_manager.create_heap(0x10000, 0x10000)
        if creation & windef.CREATE_SUSPENDED:
            thread_obj.suspend_count += 1
        teb_heap = proc_obj.vas_manager.alloc_heap(thread_obj.teb_heap, ntos.TEB(self.ptr_size).sizeof())
        gdt_page = proc_obj.vas_manager.alloc_page(0x1000, PAGE_ALLOCATION_TYPE.MEM_COMMIT)
        selectors = proc_obj.gdt.setup_selector(gdt_addr=gdt_page.get_base_addr(), fs_base=teb_heap, fs_limit=mem_defs.ALLOCATION_GRANULARITY)
        thread_obj.set_selectors(selectors)
        thread_obj.init_teb(proc_obj.peb_base)
        thread_obj.init_context()
        proc_obj.uc_eng.mem_write(teb_heap, thread_obj.teb.get_bytes())
        proc_obj.push_waiting_queue(thread_obj.handle)

        return thread_obj.handle
    

    def __update_api_va_dict__(self, va, dll:str, api:str):
        self.api_va_dict[va] = (dll, api)
        pass
    


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

        self.parse_api_conf()

    def parse_api_conf(self, conf_path="./winapi.config"):
        with open(conf_path, "rt") as f:
            confs = f.readlines()
        for line in confs:
            line = line[:-1]
            if not line:
                continue
            if line[0] == "#":
                continue
            s = line.split("|")
            rettype = s[0]
            api_name = s[1]
            if len(s) > 2:
                args_types = s[2:]
            else:
                args_types = []
            self.winapi_info_dict[api_name] = {
                "rettype": rettype,
                "argc": len(args_types),
                "args_types": args_types
            }