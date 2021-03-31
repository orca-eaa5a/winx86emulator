from pymanager import mem_manager

if __name__ == "__main__":
    from unicorn.unicorn import Uc
    from unicorn.unicorn_const import UC_ARCH_X86, UC_MODE_32

    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    mem_mgr = mem_manager.MemoryManager(uc=uc)
    _p_region = mem_mgr.alloc_page(size=0x20000, allocation_type=mem_manager.PAGE_ALLOCATION_TYPE.MEM_COMMIT, alloc_base=0x400000)
    heap = mem_mgr.create_heap(size=0x100, max_size=0x1000)
    heap_seg1 = mem_mgr.alloc_heap(heap=heap, size=0xD00)
    heap_seg2 = mem_mgr.alloc_heap(heap=heap, size=0x100)
    mem_mgr.free_heap(heap=heap, address=heap_seg1)
    heap_seg3 = mem_mgr.alloc_heap(heap=heap, size=0x300)
    