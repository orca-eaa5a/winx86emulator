import ctypes
from speakeasy.struct import EmuStruct

class _FILE_CONTAINER_HDR(EmuStruct):
    def __init__(self, ptr_size):
        super().__init__(ptr_size=ptr_size)
        self.sig = ctypes.c_uint32*8
        self.size_of_file = ctypes.c_uint32
        self.padd1 = ctypes.c_uint32
        self.padd2 = ctypes.c_uint32
        self.file_name  = ctypes.c_byte*548
    
    def get_file_contents(self, buf):
        file_contents = buf[:self.size_of_file]
        return file_contents