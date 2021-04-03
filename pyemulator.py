
from fs.memoryfs import MemoryFS
from unicorn.unicorn import Uc
from unicorn.unicorn_const import UC_ARCH_X86, UC_MODE_32
import pefile
import struct
from pymanager import fs_manager, mem_manager, net_manager
from windef import mem_defs, net_defs, file_defs

class WinX86Emu:
    def __init__(self, fs:MemoryFS):
        self.uc_eng = Uc(UC_ARCH_X86, UC_MODE_32)
        self.fs_manager = fs_manager.FileIOManager(fs)
        self.mem_manager = mem_manager.MemoryManager(self.uc_eng)
        self.net_manager = net_manager.NetworkManager()

        self._pe = None
        self.entry_point = 0
        self.image_base = 0
        self.size_of_image = 0
        self.page_size = 0x1000
        self.peb_base = 0xcb000
        self.teb_base = 0xcb000+0x2000
        self.proc_default_heap = None
        self.peb_heap=None
        self.teb_heap=None

    def init_vas(self):
        unused = self.mem_manager.alloc_page(alloc_base=0,size=0x10000, allocation_type=mem_defs.PAGE_ALLOCATION_TYPE.MEM_RESERVE)
        self.peb_heap = self.mem_manager.create_heap(0x2000, 0)
        self.peb_base = self.peb_heap.base_address
        self.teb_heap = self.mem_manager.create_heap(0x1000, 0x1000)
        self.teb_base = self.teb_heap.base_address


    def load_pe(self, data):
        pe_bin = b''
        if isinstance(data, bytes) or isinstance(data, bytearray):
            pe_bin = bytes(data)
        elif isinstance(data, str):
            handle = self.fs_manager.create_file(data)
            pe_bin = self.fs_manager.read_file(handle.handle_id)
            self.fs_manager.close_file(handle.handle_id)

        else:
            raise Exception("Invalid request")

        self._pe:pefile.PE = pefile.PE(data=pe_bin)
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

        pass