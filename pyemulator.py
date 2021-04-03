
from fs.memoryfs import MemoryFS
from unicorn.unicorn import Uc
from unicorn.unicorn_const import UC_ARCH_X86, UC_MODE_32

from pymanager import fs_manager, mem_manager, net_manager

class WinX86Emu:
    def __init__(self, fs:MemoryFS):
        self.uc_eng = Uc(UC_ARCH_X86, UC_MODE_32)
        self.fs_manager = fs_manager.FileIOManager(fs)
        self.mem_manager = mem_manager.MemoryManager(self.uc_eng)
        self.net_manager = net_manager.NetworkManager()
    
    
    def load_pe(self, data):
        import pefile
        pe_bin = b''
        if isinstance(data, bytes) or isinstance(data, bytearray):
            pe_bin = bytes(data)
        elif isinstance(data, str):
            handle = self.fs_manager.create_file(data)
            pe_bin = self.fs_manager.read_file(handle.handle_id)
            self.fs_manager.close_file(handle.handle_id)

        else:
            raise Exception("Invalid request")

        pe_obj:pefile.PE = pefile.PE(pe_bin)
        