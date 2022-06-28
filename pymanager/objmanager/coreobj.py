from os.path import basename
from unicorn.x86_const import *
from struct import pack
from unicorn.unicorn_const import UC_ARCH_X86, UC_MODE_32
from objmanager.emuobj import EmuObject
from speakeasy.windows.windows.windows import CONTEXT
import speakeasy.windows.nt.ntoskrnl as ntos

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

class KernelObject(EmuObject):
    """
    Base class for Kernel objects managed by the object manager
    """

    def __init__(self, uc_eng):
        super().__init__()
        self.uc_eng = uc_eng
        self.address = None

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


class EmuThread(KernelObject):
    """
    Represents a Windows ETHREAD object that describes a
    an OS level thread
    """
    def __init__(self, proc_obj, thread_entry, stack_base=0, stack_limit=0, param=None, arch=UC_ARCH_X86, ptr_size=4):
        super(EmuThread, self).__init__(uc_eng=proc_obj.uc_eng)
        self.proc = proc_obj
        self.uc_eng = proc_obj.uc_eng
        self.object = ntos.ETHREAD(ptr_size)
        self.address = 0xFFFFFFFF
        self.tid = -1
        self.state = 'wait'
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

    def set_tid(self, tid):
        self.tid = tid

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

class EmuProcess(KernelObject):
    def __init__(
        self, 
        uc_eng,
        emulator,
        path,
        hfile,
        ptr_size=4, param=None, arch=UC_ARCH_X86, mode=UC_MODE_32):
        super().__init__(uc_eng)
        self.ptr_size = ptr_size
        # TODO:
        # implement process parameter
        self.uc_eng = uc_eng
        self.emu = emulator
        self.path = path
        self.name = basename(path)
        self.file_handle = hfile
        self.pid = -1
        self.param = param
        self.arch = arch
        self.mode = mode

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
        self.running_thread:EmuThread = None
        self.ctx_switch_hook = None
        self.emu_suspend_flag = False

    def read_mem_self(self, pMem, size):
        return self.uc_eng.mem_read(pMem, size)

    def write_mem_self(self, addr, _bytes):
        self.uc_eng.mem_write(addr, _bytes)
        pass

    def read_string(self, pMem, width=1, max_len=0):
        char = b'\xFF'
        string = b''
        i = 0

        if width == 1:
            decode = 'utf-8'
        elif width == 2:
            decode = 'utf-16le'
        else:
            raise ValueError('Invalid string encoding')

        while int.from_bytes(char, 'little') != 0:
            if max_len and i >= max_len:
                break
            char = self.read_mem_self(pMem, width)
            string += char
            if char == b'\x00\x00':
                break
            pMem += width
            i += 1

        try:
            dec = string.decode(decode, 'ignore').replace('\x00', '')
        except Exception:
            dec = string.replace(b'\x00', b'')
        return dec

    def write_string(self, pMem, _str, width=1):
        if width == 1:
            enc_fmt = 'utf-8'
        elif width == 2:
            enc_fmt = 'utf-16le'
        b_str = _str.encode(enc_fmt)
        self.write_mem_self(pMem, b_str)
        
    def exit(self):
        self.uc_eng.emu_stop()

    def get_ptr_size(self):
        return self.ptr_size
    def get_param(self):
        return self.param
    def get_arch(self):
        return self.arch
    def get_mode(self):
        return self.mode
    def set_path(self, path):
        self.path = path
    def set_name(self, name):
        self.name = name
    def set_pid(self, pid):
        self.pid = pid
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
    
    '''
    def default_heap_alloc(self, size):
        heap_seg = self.vas_manager.alloc_heap(self.proc_default_heap, size)
        return heap_seg
    
    def default_heap_free(self, pMem):
        self.vas_manager.free_heap(self.proc_default_heap, pMem)
        pass
    '''

F_GRANULARITY = 0x8
F_PROT_32 = 0x4
F_LONG = 0x2
F_AVAILABLE = 0x1

A_PRESENT = 0x80

A_PRIV_3 = 0x60
A_PRIV_2 = 0x40
A_PRIV_1 = 0x20
A_PRIV_0 = 0x0

A_CODE = 0x10
A_DATA = 0x10
A_TSS = 0x0
A_GATE = 0x0

A_EXEC = 0x8
A_DATA_WRITABLE = 0x2
A_CODE_READABLE = 0x2

A_DIR_CON_BIT = 0x4

S_GDT = 0x0
S_LDT = 0x4
S_PRIV_3 = 0x3
S_PRIV_2 = 0x2
S_PRIV_1 = 0x1
S_PRIV_0 = 0x0

class EmuGDT:
    def __init__(self, uc_eng):
        self.uc_eng = uc_eng
        self.fs_index = 0xe
        self.gs_index = 0xf
        self.ds_index = 0x10
        self.cs_index = 0x11
        self.ss_index = 0x12

    def create_gdt_entry(self, base, limit, access, flags):
        to_ret = limit & 0xffff
        to_ret |= (base & 0xffffff) << 16
        to_ret |= (access & 0xff) << 40
        to_ret |= ((limit >> 16) & 0xf) << 48
        to_ret |= (flags & 0xff) << 52
        to_ret |= ((base >> 24) & 0xff) << 56
        return pack('<Q', to_ret)

    def create_selector(self, idx, flags):
        to_ret = flags
        to_ret |= idx << 3
        return to_ret

    def setup_selector(self, gdt_addr=0x80043000, gdt_limit=0x1000, gdt_entry_size=0x8, fs_base=None, fs_limit=None, gs_base=None, gs_limit=None, segment_limit=0xffffffff):
        gdt_entries = [self.create_gdt_entry(0, 0, 0, 0) for i in range(0x34)]

        if fs_base != None and fs_limit != None:
            gdt_entries[self.fs_index] = self.create_gdt_entry(
                fs_base, 
                fs_limit, 
                A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_0 | A_DIR_CON_BIT,F_PROT_32
            )
        else:
            gdt_entries[self.fs_index] = self.create_gdt_entry(0,
                segment_limit,
                A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT, F_PROT_32
            )

        if gs_base != None and gs_limit != None:
            gdt_entries[self.gs_index] = self.create_gdt_entry(
                gs_base,
                gs_limit,
                A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT,
                F_PROT_32
            )
        else:
            gdt_entries[self.gs_index] = self.create_gdt_entry(
                0,
                segment_limit,
                A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT,
                F_PROT_32
            )

        gdt_entries[self.ds_index] = self.create_gdt_entry(
            0,
            segment_limit,
            A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT,
            F_PROT_32
        )
        gdt_entries[self.cs_index] = self.create_gdt_entry(
            0,
            segment_limit,
            A_PRESENT | A_CODE | A_CODE_READABLE | A_PRIV_3 | A_EXEC | A_DIR_CON_BIT,
            F_PROT_32
        )
        gdt_entries[self.ss_index] = self.create_gdt_entry(
            0,
            segment_limit,
            A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_0 | A_DIR_CON_BIT,
            F_PROT_32
        )
        try:
            self.uc_eng.mem_map(gdt_addr, gdt_limit)
        except Exception as e:
            abcd = "1234"

        for idx, value in enumerate(gdt_entries):
            offset = idx * gdt_entry_size
            self.uc_eng.mem_write(gdt_addr+offset, value)

        gdtr = (0, gdt_addr, len(gdt_entries) * gdt_entry_size - 1, 0x0)
        fs = self.create_selector(self.fs_index, S_GDT | S_PRIV_0)
        gs = self.create_selector(self.gs_index, S_GDT | S_PRIV_3)
        ds = self.create_selector(self.ds_index, S_GDT | S_PRIV_3)
        cs = self.create_selector(self.cs_index, S_GDT | S_PRIV_3)
        ss = self.create_selector(self.ss_index, S_GDT | S_PRIV_0)

        return (gdtr, fs, gs, ds, cs, ss)

    def set_fs_register(self, fs_base, fs_limit, gdt_addr=0x80043000, gdt_limit=0x1000, gdt_entry_size=0x8):
        _fs = self.create_gdt_entry(fs_base, fs_limit, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_0 | A_DIR_CON_BIT, F_PROT_32)
        offset = self.fs_index*gdt_entry_size
        self.uc_eng.mem_write(gdt_addr+offset, _fs)
        self.uc_eng.reg_write(UC_X86_REG_FS, self.create_selector(self.fs_index, S_GDT | S_PRIV_0))