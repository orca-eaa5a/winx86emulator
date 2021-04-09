from pymanager.defs.mem_defs import PAGE_SIZE, ALLOCATION_GRANULARITY, PAGE_ALLOCATION_TYPE, PAGE_PROTECT, HEAP_OPTION, PAGE_TYPE
from unicorn.unicorn import Uc

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
        self.heap_handle=handle
        self.address=address
        self.size=size

    def get_buf_range(self):
        return self.address, self.address + self.size


class Heap(PageRegion):
    def __init__(self, heap_handle, page_region:PageRegion, fixed):
        super().__init__(page_region.address, 
                        page_region.size, 
                        page_region.allocation_type, 
                        page_region.protect, 
                        page_region.page_type)
        self.heap_handle=heap_handle
        self.fixed = fixed
        self.heap_space=[]
        self.used_hs = []
        self.free_hs = []
        self.append_heap_size(page_region=page_region)
        
    def append_heap_size(self, page_region:PageRegion):
        self.heap_space.append(page_region)
        self.free_hs.append(HeapFragment(
            handle=self.heap_handle,
            address=page_region.address,
            size=page_region.size
        ))
        pass

    def get_heap_handle(self):
        return self.get_heap_handle

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
                            handle=self.heap_handle,
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
                            handle=self.heap_handle,
                            address=t_fh.address + size,
                            size=t_fh.size - size
                        )
        heap_space = self.get_free_heap_space()
        heap_space.remove(t_fh)
        heap_space.insert(idx,renew_fh_seg)
        
        renew_uh_seg = HeapFragment(
                            handle=self.heap_handle,
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


class MemoryManager:
    def __init__(self, uc:Uc):
        self.emu_mem=uc
        self.page_regions=[] # : Page class list
        #self.heap_list=[]
    '''
    def add_heap_list(self, new_heap):
        self.page_regions.append(new_heap)
        self.arrange_mem_list()
    '''
    def add_page_list(self, new_region):
        self.page_regions.append(new_region)
        self.arrange_mem_list()

    def get_page_list(self):
        return self.page_regions

    def arrange_mem_list(self):
        self.page_regions.sort(key=lambda x: x.base_address, reverse=True)

    def get_availabe_page_region(self, size):
        alloc_base = 0
        '''
        for page_region in self.page_regions:
            base, limit = page_region.get_page_region_range()
            if (base - _limit) > size:
                base_addr=base
                return base_addr
            else:
                _limit = limit
        '''
        cnt = 0
        if not self.page_regions:
            return 0
        while True:
            base = ALLOCATION_GRANULARITY*cnt
            try:
                self.emu_mem.mem_map(base, size)
                self.emu_mem.mem_unmap(base, size)
                break
            except Exception as e:
                cnt+=1

        return base
        
    def vas_mem_map(self, new_region):
        self.emu_mem.mem_map(
            address=new_region.get_base_addr(),
            size=new_region.get_size())
        pass

    def vas_mem_unmap(self, page_region):
        self.emu_mem.mem_unmap(
            page_region.base_address,
            page_region.size
        )
        
    def split_page_region(self, page_base, address=0, size=0):
        pg_rg = None
        idx = 0

        # find the page region by base addr
        for page_region in self.page_regions:
            if page_base == page_region.base_address:
                pg_rg:PageRegion = page_region
                break
            idx+=1

        if address == 0 and size == 0:
            raise Exception("Invalid Parameter (address , size)")
        else:
            _pg_list = []

            if address != 0 and size != 0:
                if address % PAGE_SIZE != 0:
                    address += ( address - address%PAGE_SIZE )
                pg1_base = pg_rg.base_address
                pg1_size = address - pg_rg.base_address

                pg2_base = pg1_base + pg1_size
                address = pg2_base + size
                if address % PAGE_SIZE != 0:
                    address += ( address - address%PAGE_SIZE )
                pg2_size = address - pg2_base
                pg3_base = pg2_base + pg2_size
                pg3_size = pg_rg.base_address + pg_rg.size - pg3_base

                _pg_list.append((pg1_base, pg1_size))
                _pg_list.append((pg2_base, pg2_size))
                _pg_list.append((pg3_base, pg3_size))
                
            else:
                if address == 0 and size != 0:
                    address = pg_rg.base_address + size

                if address % PAGE_SIZE != 0:
                    address += ( address - address%PAGE_SIZE )

                pg_sz = address - pg_rg.base_address
                _pg_list.append((pg_rg.base_address, pg_sz))
                _pg_list.append((address, pg_rg.size - pg_sz))


            base, limit = pg_rg.get_page_region_range()
            #if address < base or limit < (address + size):
            #    raise Exception("Invalid Parameter (address or size)")
            
            cnt = 0
            self.page_regions.remove(pg_rg)
            for _pg in _pg_list:
                p_addr, p_sz = _pg
                _region=PageRegion(
                    address=p_addr,
                    size=p_sz,
                    allocation_type=pg_rg.get_allocation_type(),
                    protect=PAGE_PROTECT.PAGE_EXECUTE_READWRITE,
                    page_type=pg_rg.page_type
                    )
                self.page_regions.insert(idx+cnt, _region)
                cnt += 1
            
        pass  

    def create_heap(self, size, max_size, option=HEAP_OPTION.HEAP_CREATE_ENABLE_EXECUTE)->Heap:
        handle=0xFFFFFFFF
        if max_size:
            size=max_size
            if size % PAGE_SIZE != 0:
                #Upperbound
                size += ( PAGE_SIZE - size % PAGE_SIZE )
            _p_region = self.alloc_page(size=size, allocation_type=PAGE_ALLOCATION_TYPE.MEM_COMMIT, protect=PAGE_PROTECT.PAGE_EXECUTE_READWRITE)
            heap=Heap(heap_handle=handle, page_region=_p_region, fixed=True)
        else:
            if size % PAGE_SIZE != 0:
                #Upperbound
                size += ( PAGE_SIZE - size % PAGE_SIZE )
            _p_region = self.alloc_page(size=size, allocation_type=PAGE_ALLOCATION_TYPE.MEM_COMMIT, protect=PAGE_PROTECT.PAGE_EXECUTE_READWRITE)
            heap=Heap(heap_handle=handle, page_region=_p_region, fixed=False)

        return heap

    def alloc_heap(self, heap:Heap, size)->HeapFragment:
        heap_seg = heap.allocate_heap_segment(size=size)
        
        if heap_seg == 0xFFFFFFFF and not heap.is_fixed():
            _p_region = self.alloc_page(size=size, allocation_type=PAGE_ALLOCATION_TYPE.MEM_COMMIT, protect=PAGE_PROTECT.PAGE_EXECUTE_READWRITE)
            heap.append_heap_size(page_region=_p_region)
            heap_seg = heap.allocate_heap_segment(size=size)
        elif heap_seg == 0xFFFFFFFF and heap.is_fixed():
            raise Exception("No Available Heap Space")

        return heap_seg

    def free_heap(self, heap:Heap, address):
        heap.free_heap_segment(address=address)
        pass

    def destory_heap(self, heap:Heap):
        for heaps in heap.heap_space():
            self.vas_mem_unmap(heaps)
        pass

    def alloc_page(self, size, allocation_type, alloc_base=0, protect=PAGE_PROTECT.PAGE_EXECUTE_READWRITE, page_type=PAGE_TYPE.MEM_PRIVATE)->PageRegion:
        ### if alloc_base is 0, Emulator find the first fit memory region ###

        if size % PAGE_SIZE != 0:
            #Upperbound
            size += ( PAGE_SIZE - size % PAGE_SIZE )

        if alloc_base < 0:
            raise Exception("Invalid Memory Allocation Request (allocation base < 0)")
        if size < 1 :
            raise Exception("Invalid Memory Allocation Request (size < 0)")
        if alloc_base == 0:
            alloc_base = self.get_availabe_page_region(size=size)
            if alloc_base == -1:
                raise Exception("No Available Memory Space")

        _p_region=PageRegion(
                    address=alloc_base,
                    size=size,
                    allocation_type=allocation_type,
                    protect=protect,
                    page_type=page_type
                    )
        self.add_page_list(new_region=_p_region)
        self.vas_mem_map(new_region=_p_region)

        return _p_region
    
    def free_page(self, page_base, size=0): # if size = 0, free all page
        tg_page_region = None
        if size != 0:
            self.split_page_region(page_base=page_base, size=size)

        for pg_rg in self.get_page_list():
            if pg_rg.base_address == page_base:
                tg_page_region = pg_rg
                break
        if tg_page_region == None:
            raise Exception("Invalid Page Base to Free")

        self.vas_mem_unmap(tg_page_region)
        self.get_page_list().remove(tg_page_region)
        pass
        
            
