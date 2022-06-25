from os.path import basename
from typing import Tuple, Dict
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

def emu_path_join(path1, *args):
    for _path in args:
        if _path[0] == "/":
            path1+=_path
        else:
            path1+= "/" + _path

    return path1

def splitdrive(p):
    # modify splitdrive of https://github.com/python/cpython/blob/3.10/Lib/ntpath.py
    """Split a pathname into drive/UNC sharepoint and relative path specifiers.
    Returns a 2-tuple (drive_or_unc, path); either part may be empty.
    If you assign
        result = splitdrive(p)
    It is always true that:
        result[0] + result[1] == p
    If the path contained a drive letter, drive_or_unc will contain everything
    up to and including the colon.  e.g. splitdrive("c:/dir") returns ("c:", "/dir")
    If the path contained a UNC path, the drive_or_unc will contain the host name
    and share up to but not including the fourth directory separator character.
    e.g. splitdrive("//host/computer/dir") returns ("//host/computer", "/dir")
    Paths cannot contain both a drive letter and a UNC path.
    """
    if len(p) >= 2:
        if isinstance(p, bytes):
            sep = b'/'
            altsep = b'\\'
            colon = b':'
        else:
            sep = '/'
            altsep = '\\'
            colon = ':'
        normp = p.replace(altsep, sep)
        if (normp[0:2] == sep*2) and (normp[2:3] != sep):
            # is a UNC path:
            # vvvvvvvvvvvvvvvvvvvv drive letter or UNC path
            # \\machine\mountpoint\directory\etc\...
            #           directory ^^^^^^^^^^^^^^^
            index = normp.find(sep, 2)
            if index == -1:
                return p[:0], p
            index2 = normp.find(sep, index + 1)
            # a UNC path can't have two slashes in a row
            # (after the initial two)
            if index2 == index + 1:
                return p[:0], p
            if index2 == -1:
                index2 = len(p)
            return p[:index2], p[index2:]
        if normp[1:2] == colon:
            return p[:2], p[2:]
    return p[:0], p

def parse_file_fullpath(abs_full_path:str) -> Tuple[str, str, str]:
    """_summary_
        parse input string to (volume_letter, path, file_name)
    Args:
        abs_full_path (str): string which indicate full path of file

    Returns:
        Tuple[str, str, str]: (volume_letter, path, file_name)
    """

    volume_letter, path = splitdrive(abs_full_path)
    if not volume_letter:
        return ('', '', '')
    base_name = basename(path)
    path = path[:int(-1*len(base_name))]

    return (volume_letter, path, base_name)

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

def convert_win_to_emu_iomode(dwDesiredAccess, dwCreationDisposition, dwFlagsAndAttributes) -> any:
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
        dictionary: python io mode
            "ty" : open type (file or directory)
            "nc" : create new file
            "fc" : create file new file wether file is already existing or not
            "mode" : python-like io mode
    """
    def is_directory_open(dwFlagsAndAttributes):
        if nt.FileAttribute.FILE_FLAG_BACKUP_SEMANTICS | dwFlagsAndAttributes:
            return True
        return False

    def is_create_new(dwCreationDisposition):
        if (dwCreationDisposition | nt.CreationDisposition.CREATE_ALWAYS) or \
            (dwCreationDisposition | nt.CreationDisposition.CREATE_NEW) or \
            (dwCreationDisposition | nt.CreationDisposition.OPEN_ALWAYS):
            return False
        return True

    def is_create_force(dwCreationDisposition):
        if (dwCreationDisposition | nt.CreationDisposition.CREATE_ALWAYS) or \
            (dwCreationDisposition | nt.CreationDisposition.OPEN_ALWAYS):
            return True
        return False

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
    new_create = True if is_create_new(dwCreationDisposition) else False
    create_force = True if is_create_force(dwCreationDisposition) else False
    is_overwrite = True if (dwCreationDisposition | nt.CreationDisposition.CREATE_ALWAYS) else False
    py_io_mode = convert_io_mode_to_py(dwDesiredAccess, dwFlagsAndAttributes, is_overwrite)

    return {
        'ty': open_type, # open type
        'nc': new_create, # create new file
        'cf': create_force, # create file forcefully
        'mode': py_io_mode
    }