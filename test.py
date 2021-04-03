from pymanager import mem_manager
from pymanager import fs_manager
import mmap
from pyfilesystem import emu_fs
import http
import pefile

if __name__ == "__main__":
    from unicorn.unicorn import Uc
    from unicorn.unicorn_const import UC_ARCH_X86, UC_MODE_32

    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    vfs = emu_fs.WinVFS()
    io_manager = fs_manager.FileIOManager(fs=vfs.vfs)
    
    with open("./sample/metasploit.exe", "rb") as fp:
        buf = fp.read()
    t = pefile.PE(data=buf)
    print(t)