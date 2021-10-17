from pymanager import obj_manager
from pymanager.obj_manager import EmMMFile, EmFile
from six import viewitems
from pyfilesystem import emu_fs
from pymanager.defs.file_defs import DesiredAccess, CreationDisposition
from fs.memoryfs import MemoryFS
from typing import List
import speakeasy_origin.windef.windows.windows as windef
import os.path
class PyIOMode:
    mode={
            "ro": "rb",
            "rw": "rb+", # Read/Write
            "wo": "wb", # Create New, Write Only, OverWrite
            "wr": "wb+", # Create New, Read/Write, OverWrite
            "wa": "ab", # Create New, Append, Write Only
            "aa": "ab+" # Create New, Append, Read/Write
        }

class WinIOMode:
    c_disposition=CreationDisposition()
    d_access=DesiredAccess()

class EmFileManager:
    def __init__(self):
        #self.file_handle_list = []
        self.mmf_handle_list = []

    def create_file_handle(self, fp):
        file_handle=obj_manager.ObjectManager.create_new_object(EmFile, fp)
        #self.add_file_handle(file_handle)

        return file_handle

    def create_file_mapping_handle(self, file_handle, map_max, protect, name)->EmMMFile:
        file_obj = obj_manager.ObjectManager.get_obj_by_handle(file_handle)
        mmf_handle = obj_manager.ObjectManager.create_new_object(EmMMFile, file_obj.fp, map_max, protect, name, file_handle)
        self.add_mmf_handle(mmf_handle)

        return mmf_handle

    def close_file_handle(self, file_handle):
        _file_handle = None
        file_obj = obj_manager.ObjectManager.get_obj_by_handle(file_handle)
        if file_obj or not 0xFFFFFFFF:
            file_obj.fp.close()
        else:
            return False
        return True

    def add_mmf_handle(self, mmf_handle):
        self.mmf_handle_list.append(mmf_handle)

    def get_mmfobj_by_viewbase(self, view_base)->EmMMFile:
        for handle in self.mmf_handle_list:
            obj = obj_manager.ObjectManager.get_obj_by_handle(handle)
            if obj.get_view_base() == view_base:
                return obj
        return None


class FileIOManager:
    def __init__(self, fs:MemoryFS()):
        self.file_system:MemoryFS()=fs
        self.py_io_mode=PyIOMode.mode
        self.win_io_mode=WinIOMode()
        self.file_handle_manager=EmFileManager()
        self.working_dir = "c:/users/orca/desktop"

    def make_virtual_dir(self, virtual_dir_path, force=False):
        if "/" in virtual_dir_path:
            if force:
                _path = ""
                paths = virtual_dir_path.split("/")
                for _dir in paths:
                    _path += _dir
                    if not self.file_system.exists(_path):
                        self.file_system.makedir(_path)
                    _path+="/"
            else:
                if not self.file_system.exists(virtual_dir_path):
                    self.file_system.makedir(virtual_dir_path)
            return True
        else:
            return False
         
    def write_virtual_file(self, virtual_file_full_path, _bytes, force=False):
        # if force, create all directory, after then write the file
        virtual_file_full_path = self.convert_path_unix_fmt(virtual_file_full_path)
        if force:
            virtual_dir_path = "/".join(virtual_file_full_path.split("/")[0:-1])
            self.make_virtual_dir(virtual_dir_path, force=force)
        self.file_system.writebytes(virtual_file_full_path, _bytes)
        pass

    def read_virtual_file(self, file_full_path):
        pass
    def delete_virtual_file(self, file_full_path):
        pass

    def convert_path_unix_fmt(self, file_path:str):
        return file_path.replace("\\", "/").lower()

    def set_current_dir(self, d):
        d = self.convert_path_unix_fmt(d)
        self.working_dir = d

    # Change the Windows IO mode to Python IO Mode
    def convert_io_mode(self, f_name, desired_access, c_dispotion)->str:
        f_name = self.convert_path_unix_fmt(file_path=f_name)
        mode=""
        # Over Privileged Policy
        if self.is_only_fname(f_name):
            f_name = self.working_dir + "/" + f_name
        if self.file_system.exists(f_name): # If file alread exist
            if c_dispotion in [self.win_io_mode.c_disposition.OPEN_ALWAYS,
                            self.win_io_mode.c_disposition.OPEN_EXISTING,
                            self.win_io_mode.c_disposition.CREATE_NEW]: # R/W
                if desired_access & self.win_io_mode.d_access.FILE_APPEND_DATA:
                    mode=self.py_io_mode["aa"]
                else:
                    mode=self.py_io_mode["rw"]
            elif c_dispotion == self.win_io_mode.c_disposition.TRUNCATE_EXISTING: # Create New and R/W
                mode=self.py_io_mode["wr"]
            else: # CREATE_ALWAYS
                if desired_access & self.win_io_mode.d_access.FILE_APPEND_DATA:
                    mode=self.py_io_mode["aa"]
                else:
                    mode=self.py_io_mode["wr"]
        else:
            if c_dispotion == self.win_io_mode.c_disposition.OPEN_EXISTING:
                raise Exception("File is not exist")
            elif c_dispotion in [self.win_io_mode.c_disposition.CREATE_NEW, 
                                self.win_io_mode.c_disposition.CREATE_ALWAYS,
                                self.win_io_mode.c_disposition.OPEN_ALWAYS]:
                mode=self.py_io_mode["wr"]
            else: # TRUNCATE_EXISTING
                raise Exception("File is not exist")
        
        return mode
    
    def is_only_fname(self,file_path):
        file_path = self.convert_path_unix_fmt(file_path=file_path)
        if "/" not in file_path:
            return True
        else:
            return False

    def create_file(self, file_path, mode=None)->EmFile:
        if not mode:
            mode=self.py_io_mode["ro"] # Read Only
        file_path = self.convert_path_unix_fmt(file_path)
        if "./" in file_path or "../" in file_path:
            file_path = self.get_relative_path(file_path)
        else:
            if self.is_only_fname(file_path=file_path):
                file_path = self.working_dir + "/" + file_path
        try:
            fp = self.file_system.open(file_path, mode)
            file_handle = self.file_handle_manager.create_file_handle(fp)
        except FileNotFoundError:
            file_handle = windef.INVALID_HANDLE_VALUE
        
        return file_handle

    def write_file(self, file_handle, data):
        file_obj = obj_manager.ObjectManager.get_obj_by_handle(file_handle)
        file_obj.fp.write(data)
        file_obj.fp.flush()

        return len(data)

    def read_file(self, file_handle, read_bytes=0xFFFFFFFF)->bytes:
        file_obj = obj_manager.ObjectManager.get_obj_by_handle(file_handle)

        if read_bytes == 0xFFFFFFFF:
            buf = file_obj.fp.read() # Read ALL
        else:
            buf = file_obj.fp.read(read_bytes)

        return buf

    def close_file(self, file_handle):
        self.file_handle_manager.close_file_handle(file_handle)

    def create_file_mapping(self, file_handle, map_max, protect, name)->EmMMFile:
        if file_handle == 0xFFFFFFFF: # Invalid File Handle
            file_handle = self.create_file("C:/pagefile.sys", "wb+")
        mmf_handle = self.file_handle_manager.create_file_mapping_handle(file_handle, map_max, protect, name)

        return mmf_handle

    def set_map_object(self, file_handle, offset, map_region)->EmMMFile:
        mmf_obj:EmMMFile = obj_manager.ObjectManager.get_obj_by_handle(file_handle)
        self.set_file_pointer(file_handle, offset)
        mmf_obj.set_view(map_region)

        return mmf_obj

    def get_file_pointer(self, file_handle):
        file_obj = obj_manager.ObjectManager.get_obj_by_handle(file_handle)
        return file_obj.fp.ftell()
    
    def set_file_pointer(self, file_handle, offset):
        file_obj = obj_manager.ObjectManager.get_obj_by_handle(file_handle)
        return file_obj.fp.seek(offset)

    def get_current_directory(self):
        return self.working_dir
    
    def set_current_directory(self, dir_path):
        dir_path = self.convert_path_unix_fmt(dir_path)
        if self.file_system.exists(dir_path):
            self.working_dir = dir_path

            return self.working_dir
        else:
            raise Exception("Directory is not exist")
            return ""

    def get_relative_path(self, file_path):
        paths = file_path.split("/")
        if paths[0] == ".":
            return "/".join([self.working_dir] + paths[1:])

        relative_dir = self.working_dir.split("/")

        for path in paths:
            if path == "..":
                relative_dir = relative_dir[:-1]
            else:
                relative_dir.append(path)
        

        return "/".join(relative_dir)