from unicorn.unicorn_const import UC_MEM_WRITE

class Dispatcher(object):
    mmf_counter_tab = {}

    @staticmethod 
    def fetch_all_region(eng, mmf_obj):
        view_base = mmf_obj.get_view_base()
        b = eng.mem_read(view_base, mmf_obj.maximum_size)
        mmf_obj.fetch_data(b)

    @staticmethod
    def file_map_dispatcher(uc, access, address, size, value, d):
        # Dispatching all memory region for every 10 times instruction
        if access != UC_MEM_WRITE:
            return
        proc, mmf_obj = d
        view_base = mmf_obj.get_view_base()

        if not view_base in Dispatcher.mmf_counter_tab:
            Dispatcher.mmf_counter_tab[view_base] = 0
        
        if Dispatcher.mmf_counter_tab[view_base] == 10:
            Dispatcher.fetch_all_region(proc.uc_eng, mmf_obj)