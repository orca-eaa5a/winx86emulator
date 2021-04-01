import fs


# read windows vdm file and unpack its contents at vfs
class WinVFS: 
    def __init__(self):
        self.vfs=fs.open_fs("mem://")
        self.InitWindowsDefaultFiles()
        
    def InitWindowsDefaultFiles(self):
        self.vfs.makedirs("C:") # Make C Drive
        self.vfs.makedirs("D:") # Make C Drive
        self.vfs.makedirs("E:") # Make C Drive
        self.vfs.makedirs("F:") # Make C Drive
        self.vfs.touch("C:/pagefile.sys") # PageFile for MMF
        self.vfs.makedirs("C:/Windows")
        self.vfs.makedirs("C:/Windows/System32")
        self.vfs.makedirs("C:/Users/orca/Desktop")
        pass