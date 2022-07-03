from unicorn.unicorn import  Uc
from unicorn.unicorn_const import UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_HOOK_MEM_UNMAPPED, UC_MEM_WRITE_UNMAPPED, UC_MEM_READ_UNMAPPED
from unicorn.x86_const import UC_X86_REG_EIP

def invalid_mem_access_cb(uc:Uc, access, address, size, value, user_data):
    uc.emu_stop()
    eip = uc.reg_read(UC_X86_REG_EIP)
    print (">>> eip at 0x%x" % eip)
    if access == UC_MEM_WRITE_UNMAPPED:
        print(">>> Missing memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" % (address, size, value))
        raise Exception("err : UC_MEM_WRITE_UNMAPPED")
    elif access == UC_MEM_READ_UNMAPPED:
        print(">>> Missing memory is being Read at 0x%x" % (address))
        raise Exception("err : UC_MEM_READ_UNMAPPED")

