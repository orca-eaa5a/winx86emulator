from pymanager import obj_manager
from pymanager.defs.mem_defs import PAGE_SIZE, ALLOCATION_GRANULARITY, PAGE_ALLOCATION_TYPE, PAGE_PROTECT, HEAP_OPTION, PAGE_TYPE
from unicorn.unicorn import Uc
from pymanager.obj_manager import *

'''
class MemoryManager:
    def __init__(self, uc:Uc):
        self.emu_mem=uc
        self.page_regions=[] # : Page class list
        self.heap_list=[]

    def add_heap_list(self, heap:Heap):
        self.heap_list.append(heap)

    def delete_heap_from_list(self, heap):
        self.heap_list.remove(heap)

    def get_heap_by_handle(self, handle_id):
        for heap in self.heap_list:
            if handle_id == heap.handle:
                return heap
        return None

    def add_page_list(self, new_region):
        self.page_regions.append(new_region)
        self.arrange_mem_list()

    def get_page_list(self):
        return self.page_regions

    def arrange_mem_list(self):
        self.page_regions.sort(key=lambda x: x.base_address, reverse=True)

    def get_availabe_page_region(self, size):
        alloc_base = 0
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
        if max_size:
            size=max_size
            if size % PAGE_SIZE != 0:
                #Upperbound
                size += ( PAGE_SIZE - size % PAGE_SIZE )
            _p_region = self.alloc_page(size=size, allocation_type=PAGE_ALLOCATION_TYPE.MEM_COMMIT, protect=PAGE_PROTECT.PAGE_EXECUTE_READWRITE)
            h = obj_manager.ObjectManager.create_new_object(Heap, _p_region, True)
        else:
            if size % PAGE_SIZE != 0:
                #Upperbound
                size += ( PAGE_SIZE - size % PAGE_SIZE )
            _p_region = self.alloc_page(size=size, allocation_type=PAGE_ALLOCATION_TYPE.MEM_COMMIT, protect=PAGE_PROTECT.PAGE_EXECUTE_READWRITE)
            h = obj_manager.ObjectManager.create_new_object(Heap, _p_region, False)
        heap = obj_manager.ObjectManager.get_obj_by_handle(h)
        self.add_heap_list(heap)

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

    def free_heap(self, handle, address):
        heap = obj_manager.ObjectManager.get_obj_by_handle(handle)
        heap.free_heap_segment(address=address)
        pass

    def destroy_heap(self, handle):
        heap = obj_manager.ObjectManager.get_obj_by_handle(handle)
        for heaps in heap.heap_space:
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
        
    def get_page_region_from_baseaddr(self, page_base):
        for pg_rg in self.get_page_list():
            if pg_rg.base_address == page_base:
                return pg_rg
        return None
'''

class MemoryManager:
    def __init__(self) -> None:
        '''
        vas_mngment_block = {
            "pid": pid,
            "proc_obj": obj,
            "page": [],
            "heap": []
        }
        '''
        self.proc_obj_list = []
        self.page_regions=[] # : Page class list
        self.heap_list=[]
    
    def register_new_process(self, proc_obj):
        self.proc_obj_list.append(
            {
                "pid": proc_obj.pid,
                "proc_obj": proc_obj,
                "page": [],
                "heap": []
            }
        )

    def add_heap_list(self, heap:Heap):
        self.heap_list.append(heap)

    def delete_heap_from_list(self, heap):
        self.heap_list.remove(heap)

    def get_heap_by_handle(self, handle_id):
        for heap in self.heap_list:
            if handle_id == heap.handle:
                return heap
        return None

    def add_page_list(self, new_region):
        self.page_regions.append(new_region)
        self.arrange_mem_list()

    def get_page_list(self):
        return self.page_regions

    def arrange_mem_list(self):
        self.page_regions.sort(key=lambda x: x.base_address, reverse=True)

    def get_availabe_page_region(self, size):
        alloc_base = 0
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
        if max_size:
            size=max_size
            if size % PAGE_SIZE != 0:
                #Upperbound
                size += ( PAGE_SIZE - size % PAGE_SIZE )
            _p_region = self.alloc_page(size=size, allocation_type=PAGE_ALLOCATION_TYPE.MEM_COMMIT, protect=PAGE_PROTECT.PAGE_EXECUTE_READWRITE)
            h = obj_manager.ObjectManager.create_new_object(Heap, _p_region, True)
        else:
            if size % PAGE_SIZE != 0:
                #Upperbound
                size += ( PAGE_SIZE - size % PAGE_SIZE )
            _p_region = self.alloc_page(size=size, allocation_type=PAGE_ALLOCATION_TYPE.MEM_COMMIT, protect=PAGE_PROTECT.PAGE_EXECUTE_READWRITE)
            h = obj_manager.ObjectManager.create_new_object(Heap, _p_region, False)
        heap = obj_manager.ObjectManager.get_obj_by_handle(h)
        self.add_heap_list(heap)

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

    def free_heap(self, handle, address):
        heap = obj_manager.ObjectManager.get_obj_by_handle(handle)
        heap.free_heap_segment(address=address)
        pass

    def destroy_heap(self, handle):
        heap = obj_manager.ObjectManager.get_obj_by_handle(handle)
        for heaps in heap.heap_space:
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
        
    def get_page_region_from_baseaddr(self, page_base):
        for pg_rg in self.get_page_list():
            if pg_rg.base_address == page_base:
                return pg_rg
        return None