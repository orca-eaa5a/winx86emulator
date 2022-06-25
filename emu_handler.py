from pyfilesystem import emu_fs
import pyemulator
from pymanager.objmanager import objmanager


class EmuHandler(object):
    EMU_ID = 0xeaa5a
    vfs = emu_fs.WinVFS()
    emu_q = []
    obj_manager = objmanager.ObjectManager()

    @staticmethod
    def get_emu_id():
        EmuHandler.EMU_ID +=1
        return EmuHandler.EMU_ID

    @staticmethod
    def create_new_emulator(physical_file_path):
        if not isinstance(physical_file_path, str):
            print("first argv must be str type")
            raise TypeError
        
        new_emulator = pyemulator.WinX86Emu(None)
        new_emulator.init_emulation_environment(physical_file_path)
        EmuHandler.emu_q.append((EmuHandler.EMU_ID, new_emulator))
        EmuHandler.EMU_ID += 1
        
        return new_emulator
        
    @staticmethod
    def create_child_emulator(parent_emu):
        if not isinstance(parent_emu, pyemulator.WinX86Emu):
            print("first argv must WinX86Emu type")
            raise TypeError
        
        #child_emulator = pyemulator.WinX86Emu()

