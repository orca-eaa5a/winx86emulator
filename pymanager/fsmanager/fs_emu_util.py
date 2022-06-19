from typing import Tuple
import windefs as nt

def is_winpath(path:str) -> bool:
    if "\\" in path:
        return True
    return False
    

def is_relpath(path:str) -> bool:
    tmp_l = path.split("/")
    if (".." in tmp_l) or ("." in tmp_l):
        return True
    return False

def is_abspath(path:str) -> bool:
    if ":" in path:
        return True
    return False

def get_parent_pathstring(abs_path:str) -> str:
    """
    Args:
        abs_path (str): emulation path format(unix) string
    """
    if not is_abspath:
        raise Exception('[EMU](fsmanager) Invalid paramter error')
    idx = abs_path.rfind("/")
    if idx <= 0:
        # when parents volume letter
        return abs_path
    return abs_path[:idx]

def convert_rel_to_abspath(path:str, working_dir:str):
    if "\\" in path:
        path_string = path.lower().replace("\\", "/")
    else:
        path_string = path
    rel_path = working_dir.lower()
    for _path in path_string.split("/"):
        if _path == ".":
            continue
        elif _path == "..":
            rel_path = get_parent_pathstring(rel_path)
        else:
            rel_path = rel_path + "/" + _path
    volume_letter, path_string = rel_path.split(":")
    volume_letter = volume_letter + ":"

    return (volume_letter, path_string)

def convert_winpath_to_emupath(path:str, working_dir:str='') -> Tuple[str,str]:
    """_summary_
        Convert Windows path format to emulation path format
    Args:
        path (str): 
            Windows path format string
            Can be relative or absolute path
        working_dir (str):
            Absolute emulation path of working directory
            Only needed when path is relative path which has no volume letter
    Returns:
        (volume_letter, emu_path): 
            Set of strings converted emulation path 
    TODO:
        check whether input can be DOS like format and adapt it's format conversion
    """
    # Windows file system treats file and directory names as case-insensitive (default)
    try:
        volume_letter, path_string = path.lower().split(":")
        # general case eg.
        # volume_letter -> c:
        # path_string -> /test/test/test.txt
        if "?" in volume_letter:
            prefix = "\\\\?\\"
            volume_letter = volume_letter[len(prefix)][0]
        volume_letter = volume_letter + ":"
        path_string = path_string.replace("\\", "/")
        paths = path_string.split("/")
        if (".." in paths) or ("." in paths):
            # path_string contain relative path
            idx = 0
            if ".." in paths:
                idx = paths.index("..")
            else:
                idx = paths.index(".")
            wd = volume_letter + "/".join(paths[:idx])
            rel_path = "/".join(paths[idx:])
            volume_letter, path_string = convert_rel_to_abspath(rel_path, wd)
        
    except ValueError:
        # relative path without volume letter
        volume_letter = ''
        if not working_dir:
            raise Exception('[EMU](fsmanager) Invalid paramter error')
        volume_letter, path_string = convert_rel_to_abspath(path, working_dir)
    # check extended-length path prifix

    return {
        "vl": volume_letter,
        "ps": path_string
    }

def convert_win_to_emu_iomode(dwDesiredAccess, dwCreationDisposition, dwFlagsAndAttributes) -> str:
    """_summary_
        During emulation, emulator has most privilege policy
        Therefore, emulator give almost full privilege to emulating process
        So, just check belows.
            1. directory or file
            2. new creation, overwrite, append
    Args:
        dwDesiredAccess (_type_): _description_
        dwCreationDisposition (_type_): _description_
        dwFlagsAndAttributes (_type_): _description_

    Returns:
        str: python io mode
    """
    def is_directory_open(dwFlagsAndAttributes):
        if nt.FileAttribute.FILE_FLAG_BACKUP_SEMANTICS | dwFlagsAndAttributes:
            return True
        return False

    def is_exist_only(dwCreationDisposition):
        if (dwCreationDisposition | nt.CreationDisposition.CREATE_ALWAYS) or \
            (dwCreationDisposition | nt.CreationDisposition.OPEN_ALWAYS):
            return False
        return True

    def convert_io_mode_to_py(dwDesiredAccess, dwFlagsAndAttributes, is_overwrite):
        if (dwFlagsAndAttributes | nt.FileAttribute.FILE_ATTRIBUTE_READONLY):
            return 'rb'
        elif (dwDesiredAccess | nt.DesiredAccess.GENERIC_ALL):
            if is_overwrite:
                return 'wb+'
            else:
                return 'rb+'
        elif (dwDesiredAccess | nt.DesiredAccess.GENERIC_READ) or \
            (dwDesiredAccess | nt.DesiredAccess.FILE_READ_DATA) or \
                (dwDesiredAccess | nt.DesiredAccess.FILE_READ_EA):
            return 'rb'
        elif (dwDesiredAccess | nt.DesiredAccess.GENERIC_WRITE) or \
            (dwDesiredAccess | nt.DesiredAccess.FILE_WRITE_DATA) or \
                (dwDesiredAccess | nt.DesiredAccess.FILE_WRITE_EA):
            if is_overwrite:
                return 'wb+'
            else:
                return 'rb+'
        else:
            return 'rb+'
        

    open_type = 'directory' if is_directory_open(dwFlagsAndAttributes) else 'file'
    failed_on_not_exist = True if is_exist_only(dwCreationDisposition) else False
    is_overwrite = True if (dwCreationDisposition | nt.CreationDisposition.CREATE_ALWAYS) else False
    py_io_mode = convert_io_mode_to_py(dwDesiredAccess, dwFlagsAndAttributes, is_overwrite)

    return {
        'ty': open_type, # open type
        'eo': failed_on_not_exist, # exist only
        'mode': py_io_mode
    }