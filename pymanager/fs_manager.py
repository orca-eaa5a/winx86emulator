from pyfilesystem import emu_fs
from windef.file_defs import DesiredAccess, CreationDisposition
from fs.memoryfs import MemoryFS
from typing import List
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

class FileHandle:
    handle_id = 0x1234
    def __init__(self, handle_id, fp):
        self.handle_id=handle_id
        self.fp = fp
        self.io_mode = fp.mode
        self.name = fp.name

class MMFHandle(FileHandle):
    handle_id = 0x7890
    def __init__(self, handle_id, fp, max_size, protect, name, file_handle_id):
        super().__init__(handle_id, fp)
        self.max_size = max_size
        self.proetct = protect
        self.obj_name = name
        self.file_handle_id = file_handle_id


class FileHandleManager:
    def __init__(self):
        self.file_handle_list = []
        self.mmf_handle_list = []

    def create_file_handle(self, fp):
        file_handle=FileHandle(FileHandle.handle_id, fp)
        FileHandle.handle_id+=4
        self.add_file_handle(file_handle)

        return file_handle

    def create_file_mapping_handle(self, file_handle_id, max_size, protect, name):
        file_handle = self.get_fd_by_handle_id(file_handle_id)
        mmf_handle = MMFHandle(MMFHandle.handle_id, file_handle.fp, max_size, protect, name, file_handle_id)
        MMFHandle.handle_id+=4
        self.add_mmf_handle(mmf_handle)

        return mmf_handle

    def close_file_handle(self, handle_id):
        _file_handle = None
        for file_handle in self.file_handle_list:
            if file_handle.handle_id == handle_id:
                _file_handle = file_handle
                break
        if _file_handle == None:
            raise Exception("Invalid handle id")
        _file_handle.fp.close()
        del _file_handle
        FileHandle.handle_id-=4
        pass

    def add_file_handle(self, file_handle:FileHandle):
        if not isinstance(file_handle, FileHandle):
            raise Exception("Invalid handle type")
        self.file_handle_list.append(file_handle)
        pass
    
    def add_mmf_handle(self, mmf_handle:MMFHandle):
        if not isinstance(mmf_handle, MMFHandle):
            raise Exception("Invalid handle type")
        self.mmf_handle_list.append(mmf_handle)
        pass

    def get_fd_by_handle_id(self, handle_id)->FileHandle:
        for file_handle in self.file_handle_list:
            if file_handle.handle_id == handle_id:
                return file_handle
        return None

    def get_mmfobj_by_handle_id(self, handle_id)->MMFHandle:
        for mmf_handle in self.mmf_handle_list:
            if mmf_handle.handle_id == handle_id:
                return mmf_handle
        return None
    
    def get_obj_by_handle(self, handle_id):
        obj = None
        obj = self.get_fd_by_handle_id(handle_id)
        if obj:
            return obj
        obj = self. get_mmfobj_by_handle_id(handle_id)
        if obj:
            return obj


class FileIOManager:
    def __init__(self, fs:MemoryFS()):
        self.file_system=fs
        self.py_io_mode=PyIOMode.mode
        self.win_io_mode=WinIOMode()
        self.file_handle_manager=FileHandleManager()
        self.working_dir = "C:/Users/orca/Desktop"

    def convert_path_unix_fmt(self, file_path:str):
        return file_path.replace("\\", "/")

    # Change the Windows IO mode to Python IO Mode
    def convert_io_mode(self, f_name, desired_access, c_dispotion)->str:
        f_name = self.convert_path_unix_fmt(file_path=f_name)
        mode=""
        # Over Privileged Policy
        if self.file_system.vfs.exists(f_name): # If file alread exist
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

    def create_file(self, file_path, mode=None)->FileHandle:
        if not mode:
            mode=self.py_io_mode["rb"] # Read Only
        file_path = self.convert_path_unix_fmt(file_path)
        if "./" in file_path or "../" in file_path:
            file_path = self.__get_relative_path(file_path)
        else:
            if self.is_only_fname(file_path=file_path):
                file_path = self.working_dir + "/" + file_path
        self.__create_path(file_path=file_path)
        fp = self.file_system.open(file_path, mode)
        file_handle = self.file_handle_manager.create_file_handle(fp)

        return file_handle
    
    def create_file_mapping(self, handle_id, protect, max_size, name):
        mmf_handle = self.file_handle_manager.create_file_mapping_handle(handle_id, max, protect, name)

        return mmf_handle


    def write_file(self, handle_id, data):
        file_handle = self.file_handle_manager.get_fd_by_handle_id(handle_id)
        file_handle.fp.write(data)

        return len(data)

    def read_file(self, handle_id, read_bytes=0xFFFFFFFF):
        file_handle = self.file_handle_manager.get_fd_by_handle_id(handle_id)

        if read_bytes == -1:
            buf = file_handle.fp.read() # Read ALL
        else:
            buf = file_handle.fp.read(read_bytes)

        return buf

    def close_file(self, handle_id):
        self.file_handle_manager.close_file_handle(handle_id)

    def get_file_pointer(self, handle_id):
        file_handle = self.file_handle_manager.get_fd_by_handle_id(handle_id)
        return file_handle.fp.ftell()
    
    def set_file_pointer(self, handle_id, offset):
        file_handle = self.file_handle_manager.get_fd_by_handle_id(handle_id)
        return file_handle.fp.fseek(offset)

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

    def __get_relative_path(self, file_path):
        paths = file_path.split("/")[:-1]
        if paths[0] == ".":
            return "/".join(self.working_dir + paths[1:])

        relative_dir = self.working_dir.split("/")

        for path in paths:
            if path == "..":
                relative_dir = relative_dir[:-1]
            else:
                relative_dir.append(path)
        
        return "/".join(relative_dir)


    def __create_path(self, file_path)->List:
        file_path = self.convert_path_unix_fmt(file_path=file_path)
        paths = file_path.split("/")[:-1]
        _path = ""
        created = []
        if not self.file_system.exists("/".join(paths)):
            for dir in paths:
                _path += dir
                if not self.file_system.exists(_path):
                    self.file_system.makedir(_path)
                    created.append(_path)
                _path+="/"
        
        return created