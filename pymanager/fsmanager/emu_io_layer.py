
from io import UnsupportedOperation
from fs.errors import DirectoryExists, ResourceNotFound
from fs_emu_util import convert_winpath_to_emupath, emu_path_join

class EmuIOLayer:
    emu_fs = None
    partitions = {
        #"volule_letter": SubFS
    }
    def __init__(self, fs) -> None:
        EmuIOLayer.set_vfs(fs)
        EmuIOLayer.setup_partitions()
        pass
    
    @staticmethod
    def set_vfs(fs):
        EmuIOLayer.emu_fs = fs
    
    @staticmethod
    def setup_partitions():
        for volume in EmuIOLayer.emu_fs.listdir("/"):
            EmuIOLayer.partitions[volume] = EmuIOLayer.emu_fs.opendir("/"+volume)

    @staticmethod
    def add_volume(volume_letter:str):
        volume_letter = volume_letter.lower()
        subfs = EmuIOLayer.emu_fs.makedir(volume_letter)
        EmuIOLayer.partitions[volume_letter] = subfs

    @staticmethod
    def _get_volume(volume_letter:str) -> any:
        return EmuIOLayer.partitions[volume_letter]

    @staticmethod
    def _check_valid_voulme(volume_letter:str):
        if volume_letter in EmuIOLayer.partitions:
            return True
        return False

    @staticmethod
    def file_existing(volume_name:str, path:str, file_name:str, ftype:str) -> bool:
        """_summary_
            Check specific file or directory is in pyfilesystem.MemoryFS
        Args:
            volume_name(str): volume_name
            path (str): absolute path
                e.g) volume_name -> c:
                    path -> /test/test/test.txt
            file_name (str): file name string which want to create
            ftype (str): directory or file
        """
        file_name = file_name.lower()
        if not EmuIOLayer._check_valid_voulme(volume_name):
            return False
        o = convert_winpath_to_emupath(emu_path_join(volume_name, path))
        abs_path = emu_path_join(o["vl"], o["ps"])
        full_path = emu_path_join(abs_path, file_name)

        if ftype == 'directory':
            return EmuIOLayer.emu_fs.isdir(full_path)
        elif ftype == 'file':
            return EmuIOLayer.emu_fs.isfile(full_path)
        else:
            Exception('file_existing() invalid file type')
        
        pass
    
    @staticmethod
    def create_file(volume_name:str, path:str, file_name:str, ftype:str, turncated=False, recursive:bool=False) -> any:
        """_summary_
            Create virtual file at pyfilesystem.MemoryFS
        Args:
            volume_name(str): volume_name
            path (str): absolute path
                e.g) volume_name -> c:
                    path -> /test/test/test.txt
            file_name (str): file name string which want to create
            ftype (str): directory or file
            recursive (bool, optional): 
                create directory with recursive option
                if this option is setted, all directory related with path is created recursivly
        """
        ret = {
            'success': False,
            'fp': ''
        }
        file_name = file_name.lower()
        if not EmuIOLayer._check_valid_voulme(volume_name):
            return ret
        o = convert_winpath_to_emupath(emu_path_join(volume_name, path))
        abs_path = emu_path_join(o["vl"], o["ps"])
        full_path = emu_path_join(abs_path, file_name)

        volume = EmuIOLayer._get_volume(o["vl"])
    
        if recursive:
            paths = o["ps"].split("/")
            cur_path = ""
            for p in paths:
                cur_path += p + "/"
                try:
                    volume.makedir(cur_path)
                except DirectoryExists:
                    continue
        
        if ftype == 'directory':
            try:
                EmuIOLayer.emu_fs.makedir(full_path)
            except DirectoryExists:
                pass
        elif ftype == 'file':
            EmuIOLayer.emu_fs.create(path=full_path, wipe=turncated)
        else:
            Exception('create_file() invalid file type')

        ret["success"] = True
        ret["fp"] = full_path

        return ret

    @staticmethod
    def open_file(volume_name:str, path:str, file_name:str, ftype:str, mode:str):
        """_summary_
            Open file object which in pyfilesystem.MemoryFS
        Args:
            volume_name(str): volume_name
            path (str): absolute path
                e.g) volume_name -> c:
                    path -> /test/test/test.txt
            file_name (str): file name string which want to create
            ftype (str): directory or file
            mode (str): 
                python-like file open mode
                e.g) wb
        """
        ret = {
            "success": False,
            "fp": '',
            "ftype": '',
            "obj": None
        }
        file_name = file_name.lower()

        pinfo = convert_winpath_to_emupath(emu_path_join(volume_name, path, file_name))
        full_path = emu_path_join(pinfo["vl"], pinfo["ps"])

        ret["fp"] = full_path
        ret["mode"] = mode
        ret["ftype"] = ftype

        obj = None
        try:
            if ftype == 'directory':
                obj = EmuIOLayer.emu_fs.opendir(full_path)
            elif ftype == 'file':
                obj = EmuIOLayer.emu_fs.open(full_path, mode=mode)
            else:
                Exception('open_file() invalid file type')
        except ResourceNotFound:
            return ret

        ret["success"] = True
        ret["obj"] = obj

        return ret

    @staticmethod
    def write_data(obj, data:bytes, offset:int=-1):
        """_summary_
            Write the binary data at file object of pyfilesystem.MemoryFS
        Args:
            obj(_io.TextIOWrapper): MemoryFS file object
            data (bytes): data to write
            offset (int): 
                offset to write data.
                if offset == -1,
                    write offset is the location where file pointer located
                else,
                    write data at specific offset.
                    after write data, check current and recover original file pointer offset or not
        """
        ret = {
            "success": False,
            "fp": '',
            "ws": '', # written size
            "obj": None
        }
        old_offset = obj.tell()
        if offset != -1:
            # write data at specific offset
            obj.seek(0)
            obj.seek(offset)
        try:
            obj.write(data)
        except OSError:
            return ret
        
        if offset != -1:
            cur_offset = obj.tell()
            if cur_offset < old_offset:
                obj.seek(old_offset)
        
        ret["success"] = True
        ret["fp"] = obj.name[1:]
        ret["ws"] = len(data)
        ret["obj"] = obj

        return ret
    
    @staticmethod
    def read_data(obj, offset=-1, read_size=-1):
        """_summary_
            Read the binary data from file object of pyfilesystem.MemoryFS
        Args:
            obj(_io.TextIOWrapper): MemoryFS file object
            read_size : requested size to read. when read_size is -1, read all data from current file pointer location
            offset (int): 
                offset to read data from file.
                if offset == -1,
                    read offset is the location where file pointer located
                else,
                    read data from specific offset.
                    after read data, check current and recover original file pointer offset or not
        """
        ret = {
            "success": False,
            "fp": '',
            "rs": 0, # read size
            'data': b'',
            "obj": None
        }
        ret["fp"] = obj.name
        
        old_offset = obj.tell()
        b = b''
        if offset == -1:
            obj.seek(0)
        else:
            obj.seek(offset)
        try:
            if read_size == -1:
                b = obj.read()
            else:
                b = obj.read(read_size)
        except UnsupportedOperation:
            ret["ws"] = -1
            ret["data"] = b''
            return ret
        
        obj.seek(old_offset)

        ret["success"] = True
        ret["rs"] = len(b)
        ret["data"] = b
        ret["obj"] = obj

        return ret

    @staticmethod
    def delete_file(volume_name:str, path:str, file_name:str, ftype:str):
        ret = {
            "success": False,
            "fp": '',
        }

        o = convert_winpath_to_emupath(emu_path_join(volume_name, path))
        abs_path = emu_path_join(o["vl"], o["ps"])
        full_path = emu_path_join(abs_path, file_name)

        try:
            if ftype == 'directory':
                EmuIOLayer.emu_fs.removedir(full_path)
            elif ftype == 'file':
                EmuIOLayer.emu_fs.remove(full_path)
            else:
                Exception('delete_file() invalid file type')
        except ResourceNotFound:
            return ret
        
        ret["fp"] = full_path
        
        return ret


    # def create_file_mapping(self, file_handle, map_max, protect, name)->EmMMFile:
    #     if file_handle == 0xFFFFFFFF: # Invalid File Handle
    #         file_handle = self.create_file("C:/pagefile.sys", "wb+")
    #     mmf_handle = self.file_handle_manager.create_file_mapping_handle(file_handle, map_max, protect, name)

    #     return mmf_handle

    # def set_map_object(self, file_handle, offset, map_region)->EmMMFile:
    #     mmf_obj:EmMMFile = obj_manager.ObjectManager.get_obj_by_handle(file_handle)
    #     self.set_file_pointer(file_handle, offset)
    #     mmf_obj.set_view(map_region)

    #     return mmf_obj