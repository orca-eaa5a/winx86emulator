from fs.memoryfs import MemoryFS
from pymanager import mem_manager
from pymanager import fs_manager
import mmap
from pyfilesystem import emu_fs
import http
import pefile
import pyemulator
import pydll
import os
def locate_file_at_vfs(vfs:MemoryFS, path):
    with open(path, "rb") as f:
        f_name = os.path.split(path)[-1]
        vfs.writefile("C:/Users/orca/Desktop/"+f_name, f)
    pass



if __name__ == "__main__":
    from unicorn.unicorn import Uc
    from unicorn.unicorn_const import UC_ARCH_X86, UC_MODE_32

    vfs = emu_fs.WinVFS()

    target_file = "./sample/metasploit.exe"
    locate_file_at_vfs(vfs.vfs, target_file)
    
    emu = pyemulator.WinX86Emu(vfs.vfs)
    emu.setup_emu(target_file)
    emu.launch()