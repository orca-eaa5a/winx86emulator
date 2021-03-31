from pymanager import mem_manager
from pymanager import fs_manager
import mmap
import emu_fs

if __name__ == "__main__":
    from unicorn.unicorn import Uc
    from unicorn.unicorn_const import UC_ARCH_X86, UC_MODE_32

    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    vfs = emu_fs.WinVFS()
    io_manager = fs_manager.FileIOManager(fs=vfs.vfs)
    file_handle = io_manager.create_file("test.txt", "wb+")
    file_handle.fp.write(b'hello world!')
    io_manager.close_file(file_handle.handle_id)


    file_handle = io_manager.create_file("test.txt", "rb")
    mm = mmap.mmap(file_handle.fp.fileno(), 0)
    print(mm.read())

    