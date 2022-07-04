# 파일 권한 관리
# 파일 타입 관리

from time import time
from objmanager.emuobj import EmuObject
from pyfilesystem.emu_fs import EmuIOLayer
from fs_emu_util import parse_file_fullpath, convert_win_to_emu_iomode, convert_winpath_to_emupath, emu_path_join

class EmuFileObject(EmuObject):
    def __init__(self, path, desired_access, creation_disposition, sharemode, flags_attr) -> None:
        super().__init__()
        self.path = path
        self.ftype = ''
        self.privilege = 'reserved' # reserved
        self.sharemode = 0
        self.obj = None # pytyon MemoryFS file object
        self.timestamp = 0
        self.file_pointer = 0
        self.file_size = -1
        ret = self.im_create_file_object(self.path, desired_access, creation_disposition, sharemode, flags_attr)
        if ret["success"]:
            self.get_file_size()
        pass

    def im_create_file_object(
            self,
            file_abs_path:str,
            desired_access:int,
            creation_disposition:int,
            share_mode:int,
            flags_attr:int) -> any:
        """_summary_
            create file object
        Args:
            file_abs_path (str): absolute path of file to open
            desired_access (int): responed to dwDesiredAccess
            creation_disposition (int): responed to dwCreationDisposition
            share_mode (int): responed to dwShareMode
            flags_attr (int): responed to dwFlagsAndAttributes

        Raises:
            Exception: when io_layer.open_file is failed

        Returns:
            any: result of file object creation
        """

        def convert_sharemode(share_mode:int) -> str:
            return 0

        ret = {
            "success": False,
            "path": ''
        }

        volume_name, path, file_name = parse_file_fullpath(file_abs_path)
        if not volume_name and not path:
            # file_abs_path is not absolute path
            return ret
        mod_info = convert_win_to_emu_iomode(
            desired_access, creation_disposition, flags_attr
        )

        turncated = False
        cf = None

        # check wether we have to create a new file
        if mod_info["nc"]:
            if mod_info["cf"]:
                turncated = True
            else:
                if EmuIOLayer.file_existing(volume_name, path, file_name, mod_info["ty"]):
                    return ret
            cf = EmuIOLayer.create_file(volume_name, path, file_name, mod_info["ty"], turncated)
            if not cf["success"]:
                return ret

        of = EmuIOLayer.open_file(volume_name, path, file_name, mod_info["ty"], mod_info["mode"])

        if not of["success"]:
            raise Exception('Unknown Error : create_file_object() > open_file failed..')
        
        self.path = of["fp"]
        self.ftype = of["ftype"]
        self.sharemode = convert_sharemode(share_mode)
        self.obj = of["obj"]
        self.timestamp = int(time())
        
        self.name = file_abs_path

        ret["success"] = True
        ret["path"] = of["fp"]

        return ret
    
    def im_close_object(self):
        ret = {
            "success": False,
            "path": ''
        }
        
        self.obj.close()

        ret["success"] = True
        ret["path"] = self.path

        return ret

    def im_delete_file(self, path:str, ftype:str='file'):
        ret = {
            "success": False
        }
        vl, p = convert_winpath_to_emupath(path)
        path = emu_path_join(vl, p)
        ref_cnt = self.get_references(path)
        if ref_cnt > 0:
            return ret
        volume_name, path, file_name = parse_file_fullpath(path)
        df = EmuIOLayer.delete_file(volume_name, path, file_name, ftype)
        if not df["success"]:
            return ret

        ret["success"] = True
        return ret

    def im_write_file(self, data=bytes):
        ret = {
            "success": False,
            "path": '',
            "ws": 0
        }
        
        wd = EmuIOLayer.write_data(self.obj, data, self.file_pointer)
        if not wd["success"]:
            return ret

        self.file_pointer = self.obj.tell()

        ret["success"] = True
        ret["path"] = wd["fp"]
        ret["ws"] = wd["ws"]
        
        return ret

    def im_read_file(self, read_sz:int=-1):
        ret = {
            "success": False,
            "path": '',
            "rs": 0,
            "data": b''
        }

        rf = EmuIOLayer.read_data(self.obj, self.file_pointer, read_sz)
        if not rf["success"]:
            return ret
        
        self.file_pointer = self.obj.tell()

        ret["success"] = True
        ret["path"] = rf["fp"]
        ret["rs"] = rf["rs"]
        ret["data"] = rf["data"]

        return ret
    
    def im_get_file_pointer(self):
        return self.file_pointer

    def im_set_file_pointer(self, offset):
        return self.obj.seek(offset)

    def get_file_size(self):
        if self.file_size == -1:
            self.file_size = self.obj.seek(0, 2)
            cur_fp = self.obj.tell()
            self.obj.seek(cur_fp)
        
        return self.file_size