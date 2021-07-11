import fs
import lz4.frame
# import pyfilesystem.fs_structure as fc
import pyfilesystem.fs_structure as fc
import os
# read windows vdm file and unpack its contents at vfs

def read_wide_string(buf):
    idx = 0
    wstr = ""
    while True:
        wc = buf[idx:idx+2]
        if wc== b'\x00\x00':
            break
        wstr += wc.decode("utf-16le")
        idx+=2
    return wstr

def convert_path_unix_fmt(path):
    return path.replace("\\", "/").lower()

class WinVFS: 
    def __init__(self):
        self.ptr_size = 4
        self.vfs=fs.open_fs("mem://")
        self.init_windows_default()
        self.unpack_mock_files()

    def init_windows_default(self):
        self.vfs.makedirs("c:") # Make C Drive
        self.vfs.makedirs("d:") # Make C Drive
        self.vfs.makedirs("e:") # Make C Drive
        self.vfs.makedirs("f:") # Make C Drive
        self.vfs.touch("c:/pagefile.sys") # PageFile for MMF
        self.vfs.makedirs("c:/windows")
        self.vfs.makedirs("c:/windows/system32")
        self.vfs.makedirs("c:/users/orca/desktop")
        pass
    
    def make_path(self, path):
        paths = os.path.split(path)
        if not self.vfs.exists(paths[0]):
            self.vfs.makedirs(paths[0])
        
        return paths[0], paths[1]

    def unpack_mock_files(self):
        packed_mock_files = "filezip.bin"
        FILE_SIGNATURE = b'\x20\x00\x00\x00\x00\x44\xC9\xB3\x25\xBC\xD3\x01\x00\x44\xC9\xB3\x25\xBC\xD3\x01\x00\x44\xC9\xB3\x25\xBC\xD3\x01\x00\x00\x00\x00'
        bin = b''
        with open(os.path.split(__loader__.path)[0] + "/" + packed_mock_files, "rb") as fp:
            bin =  lz4.frame.decompress(fp.read())
        

        while True:
            next_hdr_offset = bin.find(FILE_SIGNATURE)
            if next_hdr_offset == -1:
                break
            bin = bin[next_hdr_offset:]
            hdr_list = []
            while True:
                hdr = fc._FILE_CONTAINER_HDR(self.ptr_size).cast(bin)
                hdr_list.append(hdr)
                bin = bin[hdr.sizeof():]

                if bin.startswith(FILE_SIGNATURE):
                    continue
                elif bin[4:].startswith(FILE_SIGNATURE):
                    bin = bin[4:]
                else:
                    break
            file_content = hdr.get_file_contents(bin)
            for hdr in hdr_list:
                file_name = read_wide_string(bytes(hdr.file_name))
                file_name = convert_path_unix_fmt(file_name)
                
                self.make_path(file_name)
                with self.vfs.open(file_name, "wb") as fp:
                    fp.write(file_content)

            bin = bin[len(file_content):]
        