import speakeasy_origin.windef.nt.ntoskrnl as ntos
from speakeasy_origin.windef.windows.windows import CONTEXT
from unicorn.unicorn_const import UC_ARCH_X86
from unicorn.x86_const import *

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

class KernelObject(object):
    """
    Base class for Kernel objects managed by the object manager
    """
    curr_handle = 0x220
    curr_id = 0x400

    def __init__(self, uc_eng):
        self.uc_eng = uc_eng
        self.address = None
        self.name = ''
        self.object = None
        self.ref_cnt = 0
        self.id = KernelObject.curr_id
        KernelObject.curr_id += 4

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
        return self.id

    def set_id(self, oid):
        self.id = oid

    def get_class_name(self):
        if self.object:
            return self.object.__class__.__name__

    def get_mem_tag(self):
        return 'uc_eng.struct.%s' % (self.get_class_name())

    def get_handle(self):
        tmp = KernelObject.curr_handle
        KernelObject.curr_handle += 4
        return tmp

class Thread(KernelObject):
    """
    Represents a Windows ETHREAD object that describes a
    an OS level thread
    """
    def __init__(self, uc_eng, thread_entry, stack_base=0, stack_limit=0, param=None, arch=UC_ARCH_X86, ptr_size=4):
        super(Thread, self).__init__(uc_eng=uc_eng)
        self.uc_eng = uc_eng
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

    def get_context(self):
        if self.arch == UC_ARCH_X86:
            if self.ctx:
                return self.ctx
            else: 
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
        return ctx

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

        else:
            raise Exception("Unsupported architecture")
        return self.ctx


    def set_context(self, ctx:CONTEXT):
        self.ctx = ctx
    
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

class ObjectManager(object):
    """
    Class that manages kernel objects during uc_englation
    """
            
    def __init__(self, uc_eng):
        self.uc_eng = uc_eng
        self.handles = {
            # handle : obj
        }
        self.symlinks = []
    
    def create_new_object(self, obj, *args, **kwargs):
        new_obj = obj(*args)
        new_obj.set_id(self.new_id())
        return self.add_object(new_obj)
        

    def add_object(self, obj, handle=0xFFFFFFFF):
        if handle == 0xFFFFFFFF:
            handle = self.new_handle()
        self.handles[handle] = obj
        return handle

    def dup_object_handle(self, handle):
        obj = self.get_obj_by_handle(handle)
        obj.ref_cnt += 1
        new_handle = self.new_handle()        
        self.add_object(obj, new_handle)

        return new_handle

    def new_handle(self):
        handle_id = KernelObject.curr_handle
        KernelObject.curr_handle += 4

        return handle_id

    def new_id(self):
        _id = KernelObject.curr_id
        KernelObject.curr_id += 4
        return _id

    def get_obj_by_handle(self, handle):
        if handle in self.handles:
            return self.handles.get(handle)
        else:
            raise Exception("Invalid Handle")

    def close_handle(self, handle_id):
        obj = self.get_obj_by_handle(handle_id)
        obj.ref_cnt -= 1
        if obj.ref_cnt == 0:
            del self.handles[handle_id]