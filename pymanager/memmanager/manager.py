from memmanager.windefs import PAGE_SIZE, ALLOCATION_GRANULARITY, PageAllocationType, PageProtect, PageType, HeapOption
from pymanager.objmanager.manager import ObjectManager
from pymanager.objmanager.memobj import Heap, PageRegion, HeapFragment


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
        self.proc_vas_mngment_block = []
        self.page_regions=[] # : Page class list
        self.heap_list=[]
    
    def register_new_process(self, proc_obj):
        self.proc_vas_mngment_block.append(
            {
                "pid": proc_obj.pid,
                "proc_obj": proc_obj,
                "page": [],
                "heap": []
            }
        )

    def find_block_from_pid(self, pid):
        b = None
        for block in self.proc_vas_mngment_block:
            if pid == block["pid"]:
                b = block
                break
        return b

    def read_process_memory(self, pid, addr, size):
        block = self.find_block_from_pid(pid)
        if not block:
            return -1
        buf = block["proc_obj"].uc_eng.mem_read(addr, size)
        return buf

    def write_process_memory(self, pid, addr, _bytez):
        block = self.find_block_from_pid(pid)
        if not block:
            return -1
        block["proc_obj"].uc_eng.mem_write(addr, _bytez)
        return len(_bytez)
        
    def memcpy(self, pid, addr, _bytez):
        block = self.find_block_from_pid(pid)
        if not block:
            return -1
        block["proc_obj"].uc_eng.mem_write(addr, _bytez)
        
        return len(_bytez)

    def add_heap_list(self, block, heap:Heap):
        block["heap"].append(heap)

    def delete_heap_from_list(self, block, heap):
        block["heap"].remove(heap)

    def add_page_list(self, mgmt_block, new_region):
        page_regions = mgmt_block["page"]
        page_regions.append(new_region)
        self.arrange_mem_list(page_regions)

    def get_page_list(self):
        return self.page_regions

    def arrange_mem_list(self, page_regions):
        page_regions.sort(key=lambda x: x.base_address, reverse=True)

    def get_availabe_page_region(self, pid, size):
        block = self.find_block_from_pid(pid)
        if not block:
            return -1
        proc_mem = block["proc_obj"].uc_eng
        cnt = 0
        if not block["page"]:
            return 0
        while True:
            base = ALLOCATION_GRANULARITY*cnt
            try:
                proc_mem.mem_map(base, size)
                proc_mem.mem_unmap(base, size)
                break
            except Exception as e:
                cnt+=1

        return base
        
    def split_page_region(self, mgmt_block, page_base, address=0, size=0):
        pg_rg = None
        idx = 0
        page_regions = mgmt_block["page"]
        
        # find the page region by base addr
        for page_region in page_regions:
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

            #base, limit = pg_rg.get_page_region_range()
            #if address < base or limit < (address + size):
            #    raise Exception("Invalid Parameter (address or size)")
            
            cnt = 0
            page_regions.remove(pg_rg)
            for _pg in _pg_list:
                p_addr, p_sz = _pg
                _region=PageRegion(
                    address=p_addr,
                    size=p_sz,
                    allocation_type=pg_rg.get_allocation_type(),
                    protect=PageProtect.PAGE_EXECUTE_READWRITE,
                    page_type=pg_rg.page_type
                    )
                page_regions.insert(idx+cnt, _region)
                cnt += 1
            
        pass  

    def alloc_process_memory(self, pid, size=0x1000):
        block = self.find_block_from_pid(pid)
        if not block:
            return -1

    def map_process_vas(self, proc_obj, page_region:PageRegion):
        proc_mem = proc_obj.uc_eng
        proc_mem.mem_map(
            address=page_region.base_address,
            size=page_region.size
        )
    def unmap_process_vas(self, proc_obj, page_region):
        proc_mem = proc_obj.uc_eng
        proc_mem.mem_unmap(
            address=page_region.base_address,
            size=page_region.size
        )  

    def get_page_region_from_baseaddr(self, pid, page_base):
        block = self.find_block_from_pid(pid)
        for page_region in block["page"]:
            if page_region.base_address == page_base:
                return page_region
        return None

    def alloc_page(
        self,
        pid,
        size,
        allocation_type=PageAllocationType.MEM_COMMIT,
        alloc_base=0,
        protect=PageProtect.PAGE_READWRITE,
        page_type=PageType.MEM_PRIVATE):

        block = self.find_block_from_pid(pid)
        if not block:
            return -1

        if size % PAGE_SIZE != 0:
            #Upperbound
            size += ( PAGE_SIZE - size % PAGE_SIZE )

        if alloc_base < 0:
            raise Exception("Invalid Memory Allocation Request (allocation base < 0)")
        if size < 1 :
            raise Exception("Invalid Memory Allocation Request (size < 0)")
        if alloc_base == 0:
            alloc_base = self.get_availabe_page_region(pid, size=size)
            if alloc_base == -1:
                raise Exception("No Available Memory Space")

        _p_region=PageRegion(
                    address=alloc_base,
                    size=size,
                    allocation_type=allocation_type,
                    protect=protect,
                    page_type=page_type
                    )
        
        self.map_process_vas(block["proc_obj"], _p_region)
        self.add_page_list(block, _p_region) # append management block

        return _p_region

    def free_page(self, pid, page_base, size=0):
        page_region = None
        
        block = self.find_block_from_pid(pid)
        if not block:
            return -1

        if size != 0:
            self.split_page_region(mgmt_block=block, page_base=page_base, size=size)

        for pg_rg in block["page"]:
            if pg_rg.base_address == page_base: # find the remove target page region
                page_region = pg_rg
                break
        if not page_region:
            raise Exception("Invalid Page Base to Free")

        self.unmap_process_vas(block["proc_obj"], page_region)
        block["page"].remove(page_region)

    def create_heap(self, pid, size, max_size, option=None)->Heap:
        block = self.find_block_from_pid(pid)
        if not block:
            return -1

        if max_size:
            size=max_size
            if size % PAGE_SIZE != 0:
                #Upperbound
                size += ( PAGE_SIZE - size % PAGE_SIZE )
            
            page_protect = PageProtect.PAGE_READWRITE
            if option == HeapOption.HEAP_CREATE_ENABLE_EXECUTE:
                page_protect = PageProtect.PAGE_EXECUTE_READWRITE
            _p_region = self.alloc_page(pid, size=size, allocation_type=PageAllocationType.MEM_COMMIT, protect=page_protect)
            hHeap = ObjectManager.create_new_object('Heap', pid, option, _p_region, True)

        else:
            if size % PAGE_SIZE != 0:
                #Upperbound
                size += ( PAGE_SIZE - size % PAGE_SIZE )
            page_protect = PageProtect.PAGE_READWRITE
            if option == HeapOption.HEAP_CREATE_ENABLE_EXECUTE:
                page_protect = PageProtect.PAGE_EXECUTE_READWRITE
            _p_region = self.alloc_page(pid, size=size, allocation_type=PageAllocationType.MEM_COMMIT, protect=page_protect)
            hHeap = ObjectManager.create_new_object('Heap', pid, option, _p_region, False)
        
        heap = ObjectManager.get_obj_by_handle(hHeap)
        heap.set_handle(hHeap)

        self.add_heap_list(block, heap)

        return heap

    def alloc_heap(self, heap:Heap, size)->HeapFragment:
        block = self.find_block_from_pid(heap.pid)
        if not block:
            return -1

        heap_seg = heap.allocate_heap_segment(size=size)
        
        if heap_seg == 0xFFFFFFFF and not heap.is_fixed():
            page_protect = PageProtect.PAGE_READWRITE
            if heap.option == HeapOption.HEAP_CREATE_ENABLE_EXECUTE:
                page_protect = PageProtect.PAGE_EXECUTE_READWRITE
            _p_region = self.alloc_page(heap.pid, size=size, allocation_type=PageAllocationType.MEM_COMMIT, protect=page_protect)

            heap.append_heap_size(page_region=_p_region)
            heap_seg = heap.allocate_heap_segment(size=size)
        elif heap_seg == 0xFFFFFFFF and heap.is_fixed():
            raise Exception("No Available Heap Space")

        return heap_seg

    def free_heap(self, handle, address):
        heap = ObjectManager.get_obj_by_handle(handle)
        heap.free_heap_segment(address=address)
        pass

    def destroy_heap(self, handle):
        heap = ObjectManager.get_obj_by_handle(handle)
        block = self.find_block_from_pid(heap.pid)
        if not block:
            return -1
        for heaps in heap.heap_space:
            self.unmap_process_vas(block["proc_obj"], heaps)

        self.delete_heap_from_list(block, heap)
        pass