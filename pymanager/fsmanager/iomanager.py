# 파일 권한 관리
# 파일 타입 관리
from time import time
from typing import Dict
from emu_io_layer import EmuIOLayer
from fs_emu_util import parse_file_fullpath, convert_win_to_emu_iomode, convert_winpath_to_emupath, emu_path_join

class PyIOManager:
    object_id=0xADAD
    io_object:Dict[str, Dict[str, any]] = {}
    actv_object:Dict[str, Dict[str, any]] = {}
    def __init__(self) -> None:
        self.io_layer = EmuIOLayer()
        pass
    
    def gen_new_oid(self):
        PyIOManager.object_id += 4
        return PyIOManager.object_id

    def add_object(self, oid:int, path:str, ty:str, priv:any, obj:any):
        timestamp = int(time())
        PyIOManager.io_object[oid] = {
            "path": path,
            "ty": ty,
            "priv": priv,
            "object": obj,
            "stamp": timestamp
        }
        if path in PyIOManager.actv_object:
            PyIOManager.actv_object[path]["ref_cnt"]+=1
            PyIOManager.actv_object[path]["oids"].append(oid)
        else:
            PyIOManager.actv_object[path] = {
                "ref_cnt": 1,
                "oids": [oid]
            }
        pass
    
    def get_object(self, oid:int):
        obj = None
        if oid in PyIOManager.io_object:
            obj = PyIOManager.io_object[oid]
        return obj

    def rm_object(self, oid:int):
        obj = self.get_object(oid)
        PyIOManager.actv_object[obj["path"]]["ref_cnt"]-=1
        idx = PyIOManager.actv_object[obj["path"]].index(oid)
        PyIOManager.actv_object[obj["path"]]["oids"].pop(idx)
        del PyIOManager.io_object[oid]

    def get_references(self, path:str):
        ref_cnt = PyIOManager.actv_object[path]["ref_cnt"]
        return ref_cnt

    def im_create_file_object(
            self,
            file_abs_path:str,
            desired_access:int,
            creation_disposition:int,
            flags_attr:int) -> Dict[str, Dict[bool, str, str, str, any, int, any]]:

        ret = {
            "success": False,
            "path": '',
            "mode": '',
            "ftype": '',
            "priv": '', # reserved
            "oid": 0,
            "obj": None,
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
                if self.io_layer.file_existing(volume_name, path, file_name, mod_info["ty"]):
                    return ret
            cf = self.io_layer.create_file(volume_name, path, file_name, mod_info["ty"], turncated)
            if not cf["success"]:
                return ret

        of = self.io_layer.open_file(volume_name, path, file_name, mod_info["ty"], mod_info["mode"])

        if not of["success"]:
            raise Exception('Unknown Error : create_file_object() > open_file failed..')
        
        new_oid = self.gen_new_oid()

        ret["success"] = True
        ret["path"] = of["fp"]
        ret["ftype"] = of["type"]
        ret["priv"] = 'reserved1'
        ret["oid"] = new_oid
        ret["obj"] = of["obj"]

        self.add_object(ret["oid"], ret["path"], ret["ftype"], ret["priv"], ret["obj"])

        return ret
    
    def im_close_object(self, oid:int):
        ret = {
            "success": False,
            "path": ''
        }
        io_obj = self.get_object(oid)
        if not io_obj:
            return ret
            
        path = io_obj["path"]
        io_obj["object"].close()
        self.rm_object(oid)

        ret["success"] = True
        ret["path"] = path

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
        df = self.io_layer.delete_file(volume_name, path, file_name, ftype)
        if not df["success"]:
            return ret

        ret["success"] = True
        return ret

    def im_write_file(self, oid:int, offset:int, data=bytes):
        ret = {
            "success": False,
            "path": '',
            "ws": 0
        }
        io_obj = self.get_object(oid)
        if not io_obj:
            return ret
        
        wd = self.io_layer.write_data(io_obj["object"], data, offset)
        
        if not wd["success"]:
            return ret

        ret["success"] = True
        ret["path"] = wd["fp"]
        ret["ws"] = wd["ws"]
        
        return ret

    def im_read_file(self, oid:int, offset:int=-1, read_sz:int=-1):
        ret = {
            "success": False,
            "path": '',
            "rs": 0,
            "data": b''
        }
        io_obj = self.get_object(oid)
        if not io_obj:
            return ret

        rf = self.io_layer.read_data(io_obj["object"], offset, read_sz)
        if not rf["success"]:
            return ret
        
        ret["success"] = True
        ret["path"] = rf["fp"]
        ret["rs"] = rf["rs"]
        ret["data"] = rf["data"]

        return ret