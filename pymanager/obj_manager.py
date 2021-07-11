from unicorn.unicorn import UcError
import speakeasy_origin.windef.nt.ntoskrnl as ntos
from speakeasy_origin.windef.windows.windows import CONTEXT
from unicorn.unicorn_const import UC_ARCH_X86, UC_ERR_EXCEPTION, UC_ERR_OK, UC_MODE_32
from pymanager.defs.mem_defs import PAGE_SIZE, ALLOCATION_GRANULARITY, PAGE_ALLOCATION_TYPE, PAGE_PROTECT, HEAP_OPTION, PAGE_TYPE
from unicorn.x86_const import *

from pymanager import mem_manager, obj_manager
from pymanager.defs.net_defs import InetAccessType, InternetFlag, InternetPort, IntertetService
from windef.net_defs import WinHttpFlag
import http.client
import ftplib

class SEH(object):
    """
    Implements the structures needed to support SEH handling during emulation
    """
    class ScopeRecord(object):
        def __init__(self, record):
            self.record = record
            self.filter_called = False
            self.handler_called = False

    class Frame(object):

        def __init__(self, entry, scope_table, scope_records):
            self.entry = entry
            self.scope_table = scope_table
            self.scope_records = []
            for rec in scope_records:
                SEH.ScopeRecord(rec)
                self.scope_records.append(SEH.ScopeRecord(rec))
            self.searched = False

    def __init__(self):
        self.context = None
        self.context_address = 0
        self.record = None
        self.frames = []
        self.last_func = 0
        self.last_exception_code = 0
        self.exception_ptrs = 0
        self.handler_ret_val = None

    def set_context(self, context, address=0):
        self.context = context
        self.context_address = address

    def get_context(self):
        return self.context

    def set_last_func(self, func):
        self.last_func = func

    def set_record(self, record, address=0):
        self.record = record

    def set_current_frame(self, frame):
        self.frame = frame

    def get_frames(self):
        return self.frames

    def clear_frames(self):
        self.frames = []

    def add_frame(self, entry, scope_table, records):
        frame = SEH.Frame(entry, scope_table, records)
        self.frames.append(frame)


class Page:
    def __init__(
        self, 
        address, 
        size=PAGE_SIZE, 
        allocation_type=PAGE_ALLOCATION_TYPE.MEM_RESERVE, 
        protect=PAGE_PROTECT.PAGE_EXECUTE_READWRITE,
        page_type=PAGE_TYPE.MEM_PRIVATE
    ):
        self.address=address
        self.size=size
        self.allocation_type=allocation_type
        self.protect=protect
        self.page_type=page_type

    def get_base_addr(self):
        return self.address
    
    def get_size(self):
        return self.size
    
    def get_alloc_type(self):
        return self.allocation_type

class PageRegion(Page):
    def __init__(self, address, size, allocation_type, protect, page_type):
        super().__init__(address, size, allocation_type, protect, page_type)
        self.base_address=address

    def get_allocation_type(self):
        return self.allocation_type

    def renew_page_region_size(self, new):
        self.size = new
        return self.size

    def get_page_region_range(self):
        return self.base_address, self.base_address + self.size


class HeapFragment:
    def __init__(self, handle, address, size):
        self.handle=handle
        self.address=address
        self.size=size

    def get_buf_range(self):
        return self.address, self.address + self.size


class Heap(PageRegion):
    def __init__(self, page_region:PageRegion, fixed):
        super().__init__(page_region.address, 
                        page_region.size, 
                        page_region.allocation_type, 
                        page_region.protect, 
                        page_region.page_type)
        self.handle=0xFFFFFFFF
        self.fixed = fixed
        self.heap_space=[]
        self.used_hs = []
        self.free_hs = []
        self.append_heap_size(page_region=page_region)
    

    def append_heap_size(self, page_region:PageRegion):
        self.heap_space.append(page_region)
        self.free_hs.append(HeapFragment(
            handle=self.handle,
            address=page_region.address,
            size=page_region.size
        ))
        pass

    def get_heap_handle(self):
        return self.handle

    def get_used_heap_space(self):
        return self.used_hs

    def get_free_heap_space(self):
        return self.free_hs

    def allocate_heap_segment(self, size):
        for heap_seg in self.get_free_heap_space():
            if heap_seg.size > size: # Find available free heap segment
                self.__renew_heap_space_by_alloce(size=size)
                return heap_seg.address
        
        return 0xFFFFFFFF
    
    def free_heap_segment(self, address):
        self.__renew_free_heap_space_by_free(address=address)
        pass


    def __renew_free_heap_space_by_free(self, address):
        t_uh = None
        idx = 0
        for uh in self.get_used_heap_space():
            if uh.address == address:
                t_uh = uh
                break
            idx+=1
        
        if t_uh == None:
            raise Exception("Not allocated heap free")

        _address = t_uh.address
        _size = t_uh.size

        heap_space = None
        heap_space = self.get_free_heap_space()

        merge_list = []
        for fh_seg in heap_space:
            if fh_seg.address == _address + _size:
                _size += fh_seg.size
                merge_list.append(fh_seg)
        for fh_seg in merge_list:
            heap_space.remove(fh_seg)
        del merge_list

        renew_fh_seg = HeapFragment(
                            handle=self.handle,
                            address=_address,
                            size=_size
                        )

        heap_space.append(renew_fh_seg)
        heap_space.sort(key=lambda x: x.address, reverse=True)
        
        heap_space = self.get_used_heap_space()
        heap_space.remove(t_uh)

        pass
    
    def __renew_heap_space_by_alloce(self, size):
        t_fh = None
        idx = 0
        for fh in self.get_free_heap_space():
            if fh.size > size:
                t_fh = fh
                break
            idx+=1

        if t_fh == None:
            raise Exception("No available free heap space")
        
        heap_space = None
        renew_fh_seg = HeapFragment(
                            handle=self.handle,
                            address=t_fh.address + size,
                            size=t_fh.size - size
                        )
        heap_space = self.get_free_heap_space()
        heap_space.remove(t_fh)
        heap_space.insert(idx,renew_fh_seg)
        
        renew_uh_seg = HeapFragment(
                            handle=self.handle,
                            address=t_fh.address,
                            size=size
                        )
        heap_space = self.get_used_heap_space()
        heap_space.append(renew_uh_seg)
        heap_space.sort(key=lambda x: x.address, reverse=True)


    def is_fixed(self):
        if self.fixed:
            return True
        return False



class KernelObject(object):
    """
    Base class for Kernel objects managed by the object manager
    """

    def __init__(self, uc_eng):
        self.uc_eng = uc_eng
        self.address = None
        self.name = ''
        self.object = None
        self.ref_cnt = 0
        self.oid = 0xFFFFFFFF
        self.handle = 0xFFFFFFFF

    def sizeof(self, obj=None):
        if obj:
            return obj.sizeof()
        return self.object.sizeof()

    def get_bytes(self, obj=None):
        if obj:
            return obj.get_bytes()
        return self.object.get_bytes()

    def read_back(self):
        data = self.uc_eng.mem_read(self.address, self.sizeof())
        self.object.cast(data)
        return self

    def write_back(self):
        data = self.get_bytes()
        if data and self.address:
            self.uc_eng.mem_write(self.address, data)

    def get_id(self):
        return self.oid

    def set_id(self, oid):
        self.oid = oid

    def get_class_name(self):
        if self.object:
            return self.object.__class__.__name__

    def get_mem_tag(self):
        return 'uc_eng.struct.%s' % (self.get_class_name())

    def get_handle(self):
        return self.handle

class EmThread(KernelObject):
    """
    Represents a Windows ETHREAD object that describes a
    an OS level thread
    """
    def __init__(self, proc_obj, thread_entry, stack_base=0, stack_limit=0, param=None, arch=UC_ARCH_X86, ptr_size=4):
        super(EmThread, self).__init__(uc_eng=proc_obj.uc_eng)
        self.proc = proc_obj
        self.uc_eng = proc_obj.uc_eng
        self.object = ntos.ETHREAD(ptr_size)
        self.address = 0xFFFFFFFF
        self.tid = self.get_id()
        self.modified_pc = False
        self.teb = None
        self.teb_heap = None
        self.seh = SEH()
        self.tls = []
        self.param = param
        self.message_queue = []
        self.ctx = None
        self.fls = []
        self.suspend_count = 0
        self.last_error = 0
        self.stack_base = stack_base
        self.stack_limit = stack_limit
        self.thread_entry = thread_entry
        self.process = None
        self.arch = arch
        self.ptr_size = ptr_size
        self.thread_stack_region = None
        self.ldt_selector = None

    def queue_message(self, msg):
        """
        Add a GUI message to the thread's message queue
        """
        self.message_queue.append(msg)

    def set_selectors(self, selector):
        self.ldt_selector = selector

    def setup_ldt(self):
        gdtr, fs, gs, ds, cs, ss = self.ldt_selector
        self.uc_eng.reg_write(UC_X86_REG_GDTR, gdtr)
        self.uc_eng.reg_write(UC_X86_REG_FS, fs)
        self.uc_eng.reg_write(UC_X86_REG_GS, gs)
        self.uc_eng.reg_write(UC_X86_REG_DS, ds)
        self.uc_eng.reg_write(UC_X86_REG_CS, cs)
        self.uc_eng.reg_write(UC_X86_REG_SS, ss)

    def get_seh(self):
        return self.seh

    def init_context(self):
        self.ctx = CONTEXT(self.ptr_size)
        if self.arch == UC_ARCH_X86:
            self.ctx.Edi = 0
            self.ctx.Esi = 0
            self.ctx.Eax = self.thread_entry
            self.ctx.Ebp = self.stack_base
            self.ctx.Edx = 0
            self.ctx.Ecx = 0
            self.ctx.Ebx = self.thread_entry
            self.ctx.Esp = self.stack_base
            self.ctx.Eip = self.thread_entry
            self.ctx.Dr0 = 0
            self.ctx.Dr1 = 0
            self.ctx.Dr2 = 0
            self.ctx.Dr3 = 0
            self.ctx.Dr4 = 0
            self.ctx.Dr5 = 0
            self.ctx.Dr6 = 0
            self.ctx.Dr7 = 0
            
            '''
            self.ctx.SegCs = self.uc_eng.reg_read(UC_X86_REG_CS)
            self.ctx.SegSs = self.uc_eng.reg_read(UC_X86_REG_SS)
            self.ctx.SegDs = self.uc_eng.reg_read(UC_X86_REG_DS)
            self.ctx.SegFs = self.uc_eng.reg_read(UC_X86_REG_FS)
            self.ctx.SegGs = self.uc_eng.reg_read(UC_X86_REG_GS)
            self.ctx.SegEs = self.uc_eng.reg_read(UC_X86_REG_ES)
            self.ctx.GDTR = self.uc_eng.reg_read(UC_X86_REG_GDTR)
            '''
            return self.ctx
        else:
            raise Exception("Unsupported architecture")

    def get_context(self):
        if self.arch == UC_ARCH_X86:
            ctx = CONTEXT(self.ptr_size)
            ctx.Edi = self.uc_eng.reg_read(UC_X86_REG_EDI)
            ctx.Esi = self.uc_eng.reg_read(UC_X86_REG_ESI)
            ctx.Eax = self.uc_eng.reg_read(UC_X86_REG_EAX)
            ctx.Ebp = self.uc_eng.reg_read(UC_X86_REG_EBP)
            ctx.Edx = self.uc_eng.reg_read(UC_X86_REG_EDX)
            ctx.Ecx = self.uc_eng.reg_read(UC_X86_REG_ECX)
            ctx.Ebx = self.uc_eng.reg_read(UC_X86_REG_EBX)
            ctx.Esp = self.uc_eng.reg_read(UC_X86_REG_ESP)
            ctx.Eip = self.uc_eng.reg_read(UC_X86_REG_EIP)
            ctx.Dr0 = self.uc_eng.reg_read(UC_X86_REG_DR0)
            ctx.Dr1 = self.uc_eng.reg_read(UC_X86_REG_DR1)
            ctx.Dr2 = self.uc_eng.reg_read(UC_X86_REG_DR2)
            ctx.Dr3 = self.uc_eng.reg_read(UC_X86_REG_DR3)
            ctx.Dr4 = self.uc_eng.reg_read(UC_X86_REG_DR4)
            ctx.Dr5 = self.uc_eng.reg_read(UC_X86_REG_DR5)
            ctx.Dr6 = self.uc_eng.reg_read(UC_X86_REG_DR6)
            ctx.Dr7 = self.uc_eng.reg_read(UC_X86_REG_DR7)
            '''
            ctx.EFlags = self.uc_eng.reg_read(UC_X86_REG_EFLAGS)
            ctx.SegCs = self.uc_eng.reg_read(UC_X86_REG_CS)
            ctx.SegSs = self.uc_eng.reg_read(UC_X86_REG_SS)
            ctx.SegDs = self.uc_eng.reg_read(UC_X86_REG_DS)
            ctx.SegFs = self.uc_eng.reg_read(UC_X86_REG_FS)
            ctx.SegGs = self.uc_eng.reg_read(UC_X86_REG_GS)
            ctx.SegEs = self.uc_eng.reg_read(UC_X86_REG_ES)
            self.ctx.GDTR = self.uc_eng.reg_read(UC_X86_REG_GDTR)
            '''
            
            return ctx
        else:
            raise Exception("Unsupported architecture")

    def setup_context(self):
        self.uc_eng.reg_write(UC_X86_REG_ESP, self.ctx.Esp)
        self.uc_eng.reg_write(UC_X86_REG_EBP, self.ctx.Ebp)
        self.uc_eng.reg_write(UC_X86_REG_EAX, self.ctx.Eax)
        self.uc_eng.reg_write(UC_X86_REG_EBX, self.ctx.Ebx)
        self.uc_eng.reg_write(UC_X86_REG_ECX, self.ctx.Ecx)
        self.uc_eng.reg_write(UC_X86_REG_EDX, self.ctx.Edx)
        self.uc_eng.reg_write(UC_X86_REG_ESI, self.ctx.Esi)
        self.uc_eng.reg_write(UC_X86_REG_EDI, self.ctx.Edi)
        self.uc_eng.reg_write(UC_X86_REG_DR0, self.ctx.Dr0)
        self.uc_eng.reg_write(UC_X86_REG_DR1, self.ctx.Dr1)
        self.uc_eng.reg_write(UC_X86_REG_DR2, self.ctx.Dr2)
        self.uc_eng.reg_write(UC_X86_REG_DR3, self.ctx.Dr3)
        self.uc_eng.reg_write(UC_X86_REG_DR4, self.ctx.Dr4)
        self.uc_eng.reg_write(UC_X86_REG_DR5, self.ctx.Dr5)
        self.uc_eng.reg_write(UC_X86_REG_DR6, self.ctx.Dr6)
        self.uc_eng.reg_write(UC_X86_REG_DR7, self.ctx.Dr7)
        pass
    
    def set_context(self, ctx:CONTEXT):
        self.ctx = ctx
    
    def save_context(self):
        ctx = self.get_context()
        self.set_context(ctx)
        pass

    def set_thread_stack(self, page_region):
        self.thread_stack_region = page_region

    def init_teb(self, peb_addr):
        if not self.teb:
            self.teb = ntos.TEB(self.ptr_size)

        self.teb.NtTib.StackBase = self.stack_base
        self.teb.NtTib.Self = self.teb_heap.get_base_addr()
        self.teb.NtTib.StackLimit = self.stack_limit
        self.teb.ProcessEnvironmentBlock = peb_addr

        return self.teb

    def set_teb_heap(self, heap):
        self.teb_heap = heap

    def get_teb(self):
        return self.teb.read_back()

    def set_last_error(self, code):
        self.last_error = code

    def get_last_error(self):
        return self.last_error

    def get_tls(self):
        return self.tls

    def set_tls(self, tls):
        self.tls = tls

    def get_fls(self):
        return self.fls

    def set_fls(self, fls):
        self.fls = fls

    def suspend_thread(self):
        # unicorn engine has a bug which emu_stop function only works in cb of hook, not works in calle of cb.
        # the purpose of this cb is overcome this bug.
        self.proc.emu_suspend_flag = True
        return

class EmProcess(KernelObject):
    def __init__(self, uc_eng, emulator, vas_manager, ptr_size=4, param=None, arch=UC_ARCH_X86, mode=UC_MODE_32):
        super().__init__(uc_eng)
        self.ptr_size = ptr_size
        self.param = param
        self.arch = UC_ARCH_X86
        self.mode = UC_MODE_32
        self.uc_eng = uc_eng
        self.emu = emulator
        self.vas_manager:mem_manager.MemoryManager = vas_manager
        self.pid = ObjectManager.new_pid()
        self.oid = ObjectManager.new_id()
        self.file_name = None
        self.file_handle = None
        self.peb = None
        self.peb_ldr_data = None
        self.peb_heap = None
        self.peb_base = 0
        self.parsed_pe = None
        self.image_base = 0
        self.entry_point = 0
        self.proc_default_heap = None
        self.e_dllobj = {}
        self.imports = {}
        self.api_va_dict = {}
        self.api_call_flag = (False, None)
        self.ldr_entries = []
        self.gdt = None
        self.threads = []
        self.running_thread:EmThread = None
        self.ctx_switch_hook = None
        self.emu_suspend_flag = False

    def resume(self):
        while len(self.threads) != 0:
            em_thread_handle = self.pop_waiting_queue()
            em_thread = obj_manager.ObjectManager.get_obj_by_handle(em_thread_handle)
            em_thread.setup_context()
            self.running_thread = em_thread
            try:
                self.emu_suspend_flag = False
                em_thread.uc_eng.emu_start(em_thread.ctx.Eip, 0)
            except Exception as e:
                if e.args[0] == UC_ERR_EXCEPTION:
                    em_thread.uc_eng.emu_stop()
                elif e.args[1] == UC_ERR_OK:
                    em_thread.uc_eng.emu_stop()

    def get_ptr_size(self):
        return self.ptr_size
    def get_param(self):
        return self.param
    def get_arch(self):
        return self.arch
    def get_mode(self):
        return self.mode
    def set_filename(self, file_name):
        self.file_name = file_name
    def set_filehandle(self, f_handle):
        self.file_handle = f_handle
    def set_gdt(self, gdt):
        self.gdt = gdt
    def set_peb_heap(self, peb_heap):
        self.peb_heap = peb_heap
    def set_peb_base(self,peb_base):
        self.peb_base = peb_base
    def set_parsed_pe(self, parsed_pe):
        self.parsed_pe = parsed_pe
    def set_image_base(self, image_base):
        self.image_base = image_base
    def set_ep(self, entry_point):
        self.entry_point = entry_point
    def set_proc_default_heap(self, default_heap):
        self.proc_default_heap = default_heap
    def add_e_dll_obj(self, mod_name, value):
        self.e_dllobj[mod_name] = value
    def set_imports(self, mod_name, value):
        self.imports[mod_name] = value
    def add_imports(self, mod_name, value):
        self.imports[mod_name].append(value)
    def set_api_va_dict(self, va, value):
        self.api_va_dict[va] = value
    def add_ldr_entry(self, value):
        self.ldr_entries.append(value)
    def set_peb(self, peb):
        self.peb = peb
    def set_peb_ldr(self, peb_ldr):
        self.peb_ldr_data = peb_ldr
    def append_thread_queue(self, thread_obj):
        self.threads.append(thread_obj)
    def default_heap_alloc(self, size):
        heap_seg = self.vas_manager.alloc_heap(self.proc_default_heap, size)
        return heap_seg
    
    def default_heap_free(self, pMem):
        self.vas_manager.free_heap(self.proc_default_heap, pMem)
        pass

    def push_waiting_queue(self, thread_handle):
        self.threads.append(thread_handle)
        pass

    def pop_waiting_queue(self):
        return self.threads.pop()

class ObjectManager(object):
    """
    Class that manages kernel objects during uc_englation
    """
    HANDLE_ID = 0x1000
    PROCESS_ID = 0x2000
    THREAD_ID = 0x3000
    OBJECT_ID = 0x4000


    handles = {
        # "handle_id": obj
    }
        
    @staticmethod
    def new_handle():
        handle_id = ObjectManager.HANDLE_ID
        ObjectManager.HANDLE_ID += 4

        return handle_id

    @staticmethod
    def new_id():
        _id = ObjectManager.OBJECT_ID
        ObjectManager.OBJECT_ID += 4
        return _id

    @staticmethod
    def new_pid():
        pid = ObjectManager.PROCESS_ID
        ObjectManager.PROCESS_ID += 4
        return pid

    @staticmethod
    def new_tid():
        tid = ObjectManager.THREAD_ID
        ObjectManager.THREAD_ID += 4
        return tid

    @staticmethod
    def create_new_object(obj, *args, **kwargs):
        new_obj = obj(*args)
        if isinstance(new_obj, KernelObject):
            new_obj.set_id(ObjectManager.new_id())
        return ObjectManager.add_object(new_obj)
        
    @staticmethod
    def add_object(obj, handle=0xFFFFFFFF):
        if handle == 0xFFFFFFFF:
            handle = ObjectManager.new_handle()
        obj.handle = handle
        ObjectManager.handles[handle] = obj
        return handle

    @staticmethod
    def get_obj_by_handle(handle):
        if handle in ObjectManager.handles:
            return ObjectManager.handles.get(handle)
        else:
            raise Exception("Invalid Handle")
    
    @staticmethod
    def close_handle(handle_id):
        obj = ObjectManager.get_obj_by_handle(handle_id)
        obj.ref_cnt -= 1
        if obj.ref_cnt == 0:
            del ObjectManager.handles[handle_id]

class WinInetObject(object):
    def __init__(self) -> None:
        self.handle = 0xFFFFFFFF
        super().__init__()
        pass

class WinINETInstance(WinInetObject):
    def __init__(self, agent, proxy=0,bypass=0, access_types=InetAccessType.INTERNET_OPEN_TYPE_DIRECT, flag=0):
        super().__init__()
        self.agent = agent
        if proxy == 0: # null
            self.proxy = None
        else:
            self.proxy = proxy
        if bypass == 0: # null
            self.bypass= None
        else:
            self.bypass = bypass
        self.access_types = access_types
        self.flag = flag
    

class WinHttpConnection(WinInetObject):
    def __init__(self, instance:WinINETInstance, host_name, ctx, port=InternetPort.INTERNET_DEFAULT_HTTP_PORT, svc_type=IntertetService.INTERNET_SERVICE_HTTP, flag=0):
        super().__init__()
        self.instance = instance
        self.host_name = host_name
        self.port = port
        self.ctx = ctx
        self.svc_type = svc_type
        self.http_flag=flag
        self.conn = None
        self.connect()
        self.is_ssl = False

    def connect(self):
        import ssl
        if WinHttpFlag.INTERNET_FLAG_SECURE & self.http_flag or self.port == 443:
            self.conn = http.client.HTTPSConnection(
                host=self.host_name,
                timeout=10,
                context=ssl._create_unverified_context(),
            )
            self.is_ssl = True
        else:
            self.conn = http.client.HTTPConnection(
                host=self.host_name,
                port=self.port,
                timeout=10
            )

class WinHttpRequest(WinInetObject):
    def __init__(self, instance:WinHttpConnection,  u_path, refer, accept_types=None, verb='GET', version=1.1):
        super().__init__()
        self.conn_instance = instance
        if self.conn_instance.svc_type != IntertetService.INTERNET_SERVICE_HTTP: # <-- maybe ftp
            raise Exception("Service Type is different")
        self.uPath = u_path
        self.verb=verb.lower()
        self.version=version
        self.refer=refer
        self.accept_types:List = accept_types
        self.header = {}
        self.avaliable_size = 0xFFFFFFFF
        self.resp = None

        if self.accept_types:
            _accept_types = ", ".join(self.accept_types)
            self.add_header("Accept", _accept_types)
                
        if WinHttpFlag.INTERNET_FLAG_DONT_CACHE & self.conn_instance.http_flag:
            self.header["Cache-Control"] = "no-cache"
        if WinHttpFlag.INTERNET_FLAG_FROM_CACHE & self.conn_instance.http_flag:
            self.header["Cache-Control"] = "only-if-cached"
        # if WinHttpFlag.INTERNET_FLAG_IGNORE_CERT_CN_INVALID & self.http_flag: <-- Default
        
    
    def add_header(self, key, value):
        self.header[key] = value

    def add_headers(self, hdrs):
        for key in hdrs.keys():
            self.header[key] = hdrs[key]
        pass

    def set_reqinfo(self):
        self.avaliable_size = self.resp.length

    def send_req(self, data=None):
        if self.verb == 'post':
            self.conn_instance.conn.request(
                method=self.verb.upper(), 
                url=self.uPath,
                headers=self.header,
                body=data)
        else:
            self.conn_instance.conn.request(
                method=self.verb.upper(), 
                url=self.uPath,
                headers=self.header)

        self.resp = self.conn_instance.conn.getresponse()

    def change_redirected_resp(self, resp):
        self.resp = resp

    def renew_avaliable_size(self, sz):
        self.avaliable_size -= sz

class WinFtpConnection(WinInetObject):
    
    def __init__(self, instance:WinINETInstance, url, usr_name, usr_pwd, ctx, port=InternetPort.INTERNET_DEFAULT_FTP_PORT, svc_type=IntertetService.INTERNET_SERVICE_FTP, flag=0):
        super().__init__()
        self.instance = instance
        self.url = url
        self.port = port
        self.ctx = ctx
        self.uname = usr_name
        self.pwd = usr_pwd
        self.svc_type = svc_type
        
        if self.svc_type != IntertetService.INTERNET_SERVICE_FTP:
            raise Exception("Service Type is different")
        
        self.conn = ftplib.FTP()
        self.conn.connect(self.url, self.port)
        if self.uname == None:
            self.uname = "Anonymous"
            self.pwd = ""
        self.conn.login(self.uname, self.pwd)
    
    def send_cmd(self, cmd):
        res = self.conn.sendcmd(cmd)
        return res
    
    def delete_file(self, filename):
        res = self.conn.delete(filename)
        return res