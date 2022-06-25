# 파일 권한 관리
# 파일 타입 관리

from emuobj import EmuObject
from emu_io_layer import EmuIOLayer
from fs_emu_util import parse_file_fullpath, convert_win_to_emu_iomode, convert_winpath_to_emupath, emu_path_join

class EmuFileObject(EmuObject):
    def __init__(self, path, ftype, privilege, sharemode, obj, stamp) -> None:
        super().__init__()
        self.path = path
        self.ftype = ftype
        self.privilege = privilege # reserved
        self.sharemode = sharemode
        self.object = obj # pytyon MemoryFS file object
        self.timestamp = stamp

        self.convert_path_to_emu_path()
        pass

    def convert_path_to_emu_path(self):
        ep = convert_winpath_to_emupath(self.path)
        self.path = emu_path_join(ep["vl"], ep["ps"])

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
            pass

        ret = {
            "success": False,
            "oid": 0,
        }

        volume_name, path, file_name = parse_file_fullpath(file_abs_path)
        mod_info = convert_win_to_emu_iomode(
            desired_access, creation_disposition, flags_attr
        )

        turncated = False
        cf = None

        # check wether we have to create a new file
        if mod_info["nc"]:
            if mod_info["fc"]:
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
        
        new_oid = self.gen_new_oid()

        self.add_object(new_oid, of["fp"], of["ftype"], convert_sharemode(share_mode), of["obj"])

        ret["success"] = True
        ret["oid"] = new_oid

        return ret
    
    def im_close_object(self):
        ret = {
            "success": False,
            "path": ''
        }
        io_obj = self.get_object()
        if not io_obj:
            return ret
            
        self.io_obj.close()

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

    def im_write_file(self, offset:int, data=bytes):
        ret = {
            "success": False,
            "path": '',
            "ws": 0
        }
        io_obj = self.get_object()
        if not io_obj:
            return ret
        
        wd = EmuIOLayer.write_data(io_obj, data, offset)
        
        if not wd["success"]:
            return ret

        ret["success"] = True
        ret["path"] = wd["fp"]
        ret["ws"] = wd["ws"]
        
        return ret

    def im_read_file(self, offset:int=-1, read_sz:int=-1):
        ret = {
            "success": False,
            "path": '',
            "rs": 0,
            "data": b''
        }
        io_obj = self.get_object()
        if not io_obj:
            return ret

        rf = EmuIOLayer.read_data(io_obj, offset, read_sz)
        if not rf["success"]:
            return ret
        
        ret["success"] = True
        ret["path"] = rf["fp"]
        ret["rs"] = rf["rs"]
        ret["data"] = rf["data"]

        return ret