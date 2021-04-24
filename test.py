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

import faulthandler

import emu_handler as e_handler


if __name__ == "__main__":
    from unicorn.unicorn import Uc
    from unicorn.unicorn_const import UC_ARCH_X86, UC_MODE_32


    #target_file = "./sample/MMF_example.exe"
    target_file = "./sample/create_thread_ex.exe"
    emu_handler = e_handler.EmuHandler()
    emu = emu_handler.e_emu_init(target_file)
    emu.launch()
    
    while True:
        if not e_handler.EmuHandler.emu_q:
            break
    print("Emulation Finished")
    