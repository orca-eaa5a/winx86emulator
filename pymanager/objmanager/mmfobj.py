from objmanager.emuobj import EmuObject
from objmanager.fileobj import EmuFileObject

class EmuMMFileObject(EmuObject):
    def __init__(self, file_obj:EmuFileObject, security_attributes, flprotect, max_size_high, max_size_low, name) -> None:
        super().__init__()
        self.file_obj = file_obj
        # TODO:
        # implement security_attributes
        self.security_attributes = None # Reserved
        self.protect = flprotect
        self.maximum_size = 0
        self.name = name
        self.base_address = 0
        self.base_offset = 0
        self.dispatcher = None
        self.unmap_memory_with_file()
        self.set_maximum_size(max_size_high, max_size_low)

    def set_dispatcher(self, h):
        self.dispatcher = h

    def set_maximum_size(self, max_size_high, max_size_low):
        # If this parameter and dwMaximumSizeHigh are 0 (zero), 
        # the maximum size of the file mapping object is equal to the current size of the file
        if max_size_high == 0 and max_size_low == 0:
            self.maximum_size = self.file_obj.get_file_size()
        else:
            max_size_high = max_size_high << 32
            self.maximum_size = max_size_high + max_size_low
        pass

    def map_memory_with_file(self, base_addr, foffset_high, foffset_low, map_size):
        ret = {
            "success": False,
            "data": b'',
            "mapped_size": 0
        }
        self.base_address = base_addr
        self.base_offset = foffset_high << 32 + foffset_low

        if map_size == 0:
            map_size = self.file_obj.get_file_size() - self.base_offset

        fp_old = self.file_obj.im_get_file_pointer()
        self.file_obj.im_set_file_pointer(self.base_offset)
        rf = self.file_obj.im_read_file(map_size)
        
        if not rf["success"]:
            return ret

        self.file_obj.im_set_file_pointer(fp_old)

        ret["data"] = rf["data"]
        ret["mapped_size"] = rf["rs"]
        ret["success"] = True

        return ret
    
    def unmap_memory_with_file(self):
        self.base_address = 0
        self.base_offset = -1
        self.dispatcher = None

    def fetch_data(self, data, offset=0):
        ret = {
            "success": False,
            "fs": 0
        }
        fp_old = self.file_obj.im_get_file_pointer()
        self.file_obj.im_set_file_pointer(self.base_offset + offset)
        wf = self.file_obj.im_write_file(data)
        if not wf["success"]:
            return ret
        ret["success"] = wf["success"]
        ret["fs"] = wf["ws"]
        self.file_obj.im_set_file_pointer(fp_old)

    def get_view_base(self):
        return self.base_address