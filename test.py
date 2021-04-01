from pymanager import mem_manager
from pymanager import fs_manager
import mmap
from pyfilesystem import emu_fs
import http

if __name__ == "__main__":
    from unicorn.unicorn import Uc
    from unicorn.unicorn_const import UC_ARCH_X86, UC_MODE_32

    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    vfs = emu_fs.WinVFS()
    io_manager = fs_manager.FileIOManager(fs=vfs.vfs)
    
    conn = http.client.HTTPConnection(
                host="www.google.com",
                timeout=10
            )
    conn.request("GET", "/search?q=internetopen")
    t = conn.getresponse()
    t.fp.seek(0,2)
    fsz = t.fp.tell()
    t.fp.seek(0)
    print(fsz)