from pymanager.memmanager.windefs import PAGE_SIZE, ALLOCATION_GRANULARITY, PageAllocationType, PageProtect, HeapOption, PageType
from objmanager.emuobj import EmuObject
class Page(EmuObject):
    def __init__(
        self, 
        address, 
        size=PAGE_SIZE, 
        allocation_type=PageAllocationType.MEM_RESERVE, 
        protect=PageProtect.PAGE_EXECUTE_READWRITE,
        page_type=PageType.MEM_PRIVATE
    ):
        super().__init__()
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
        self.allocation_type = allocation_type
        self.protect = protect
        self.page_type = page_type
        self.mmf_handle = 0xffffffff

    def get_allocation_type(self):
        return self.allocation_type

    def renew_page_region_size(self, new):
        self.size = new
        return self.size

    def get_page_region_range(self):
        return self.base_address, self.base_address + self.size

    def set_mmf_handle(self, handle):
        self.mmf_handle = handle

    def get_mmf_handle(self):
        return self.mmf_handle


class HeapFragment:
    def __init__(self, address, size):
        self.address=address
        self.size=size

    def get_buf_range(self):
        return self.address, self.address + self.size


class Heap(PageRegion):
    def __init__(self, pid, option, page_region:PageRegion, fixed):
        super().__init__(page_region.address, 
                        page_region.size, 
                        page_region.allocation_type, 
                        page_region.protect, 
                        page_region.page_type)
        self.fixed = fixed
        self.heap_space=[]
        self.used_hs = []
        self.free_hs = []
        self.pid = pid
        self.option = option
        self.handle = 0xffffffff
        self.append_heap_size(page_region=page_region)
    

    def append_heap_size(self, page_region:PageRegion):
        self.heap_space.append(page_region)
        self.free_hs.append(HeapFragment(
            address=page_region.address,
            size=page_region.size
        ))
        pass
    
    def set_handle(self, handle):
        self.handle = handle
    
    def get_handle(self):
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
                            address=t_fh.address + size,
                            size=t_fh.size - size
                        )
        heap_space = self.get_free_heap_space()
        heap_space.remove(t_fh)
        heap_space.insert(idx,renew_fh_seg)
        
        renew_uh_seg = HeapFragment(
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

class EmLMEM:
    def __init__(self, pMem, size, flags) -> None:
        self.base = pMem
        self.size = size
        self.flags = flags
        pass