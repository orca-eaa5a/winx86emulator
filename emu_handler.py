import os
from speakeasy_origin.struct import EmuStruct
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

def get_relative_path(file_path):
    working_dir = get_default_path()
    paths = file_path.split("/")
    if paths[0] == ".":
        return "/".join([working_dir] + paths[1:])

    relative_dir = working_dir.split("/")

    for path in paths:
        if path == "..":
            relative_dir = relative_dir[:-1]
        else:
            relative_dir.append(path)
    
    return "/".join(relative_dir)

def create_path(vfs, file_path):
    file_path = convert_path_unix_fmt(file_path)
    paths = file_path.split("/")[:-1]
    _path = ""
    created = []
    if not vfs.exists("/".join(paths)):
        for dir in paths:
            _path += dir
            if not vfs.exists(_path):
                vfs.makedir(_path)
                created.append(_path)
            _path+="/"
    
    return created

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
        if "./" in f_path or "../" in f_path:
            f_path = get_relative_path(f_path)
        f_path = convert_path_unix_fmt(f_path)
        create_path(EmuHandler.vfs.vfs, f_path)
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
            f_path = argv
            pe_bin = EmuHandler.__read_physical_file(f_path)
            EmuHandler.__e_drop_file(f_path.lower(), pe_bin) # write physical file to virtual file
            argv = pe_bin

        emu = pyemulator.WinX86Emu(EmuHandler.fs_manager, EmuHandler.net_manager, EmuHandler.obj_manager)
        EmuHandler.emu_q.append(emu)
        emu = emu.setup_emu(f_path)

        return emu

