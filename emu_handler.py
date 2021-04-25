import os
from fs.memoryfs import MemoryFS
from pyfilesystem import emu_fs
import pyemulator
from pymanager import fs_manager, mem_manager, net_manager, obj_manager

def get_default_path():
    import json
    config_path = os.path.join(os.getcwd(), "env.config")
    config = None
    with open(config_path, 'r') as f:
        config = json.load(f)
    return config.get("current_dir", '')

def convert_path_unix_fmt(f_path:str):
    return f_path.replace("\\", "/").lower()

def is_only_fname(f_path):
    f_name = os.path.split(f_path)
    if isinstance(f_name, list) and len(f_name) == 1:
        return True
    return False

class EmuHandler(object):
    EMU_ID = 0xeaa5a
    vfs = emu_fs.WinVFS()
    emu_q = []
    fs_manager = fs_manager.FileIOManager(vfs.vfs)
    net_manager = net_manager.NetworkManager()
    obj_manager = obj_manager.ObjectManager()


    @staticmethod
    def get_emu_id():
        EmuHandler.EMU_ID +=1
        return EmuHandler.EMU_ID


    @staticmethod    
    def __e_drop_file(f_path, pe_bin):
        f_name = os.path.split(f_path)[-1]
        f_path = convert_path_unix_fmt(get_default_path())
        f_path = f_path + "/" + f_name

        EmuHandler.vfs.vfs.writebytes(f_path.lower(), pe_bin)
        
    @staticmethod
    def __read_physical_file(f_path):
        with open(f_path, "rb") as f:
            buf = f.read()
        return buf

    @staticmethod
    def read_virtual_file(f_path):
        f_path = convert_path_unix_fmt(f_path)

        if is_only_fname(f_path):
            f_name = f_path
            f_path = convert_path_unix_fmt(get_default_path())
            f_path = f_path + "/" + f_name
        with EmuHandler.vfs.vfs.open(f_path, "rb") as f:
            buf = f.read()
        return buf

    @staticmethod
    def e_emu_init(argv):
        # The argument can be a PE binary or file path.
        if not EmuHandler.emu_q and isinstance(argv, str): # first call
            physical_f_path = argv
            pe_bin = EmuHandler.__read_physical_file(physical_f_path)
            EmuHandler.__e_drop_file(physical_f_path, pe_bin)
            argv = pe_bin

        emu = pyemulator.WinX86Emu(EmuHandler.fs_manager, EmuHandler.net_manager, EmuHandler.obj_manager)
        emu_id = EmuHandler.get_emu_id()
        EmuHandler.emu_q.append((emu_id, emu))
        emu = emu.setup_emu(emu_id, argv)

        return emu

