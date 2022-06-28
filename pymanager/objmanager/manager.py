from objmanager.inetobj import EmuWinInetSession, EmuWinHttpConnection, EmuWinFtpConnection, EmuWinHttpRequest
from objmanager.fileobj import EmuFileObject
from objmanager.memobj import Heap
from objmanager.coreobj import EmuThread, EmuProcess, EmuGDT

# class EmFile(KernelObject):
#     def __init__(self, fp):
#         self.fp = fp
#         self.io_mode = fp.mode
#         self.name = fp.name

# class EmMMFile(EmFile):
#     def __init__(self, fp, map_max, protect, name, file_handle):
#         super().__init__(fp)
#         self.map_max = map_max
#         self.proetct = protect
#         self.obj_name = name
#         self.file_handle = file_handle
#         self.view_region = None
#         self.offset = 0
#         self.dispatcher_hook = 0

#     def direct_write(self, data):
#         self.fp.write(data)
#         cp = self.fp.seek()
#         self.fp.flush()
#         self.fp.seek(cp)

#     def set_view(self, page_region):
#         self.view_region = page_region

#     def get_view_base(self):
#         return self.view_region.get_base_addr()

#     def get_view(self):
#         return self.view_region

#     def set_file_offset(self, offset):
#         self.offset = offset
    
#     def get_file_offset(self):
#         return self.offset

#     def set_dispatcher(self, hook):
#         self.dispatcher_hook = hook

#     def get_dispatcher(self):
#         return self.dispatcher_hook

class ObjectTable:
    def __init__(self) -> None:
        self.table = {
            'File': EmuFileObject,
            'Process': EmuProcess,
            'WinInetSession': EmuWinInetSession,
            'WinHttpConnection': EmuWinHttpConnection,
            'WinFtpConnection': EmuWinFtpConnection,
            'WinHttpRequest': EmuWinHttpRequest,
        }
        pass

class ObjectManager(object):
    """
    Class that manages kernel objects during uc_englation
    """
    HANDLE_ID = 0x1000
    PROCESS_ID = 0x4444
    THREAD_ID = 0x3000
    OBJECT_ID = 0x4
    
    EmuObjectNames = {
        'File': EmuFileObject,
        'Process': EmuProcess,
        'Thread': EmuThread,
        'Heap': Heap,
        'WinInetSession': EmuWinInetSession,
        'WinHttpRequest': EmuWinHttpRequest,
        'WinHttpConnection': EmuWinHttpConnection,
        'WinFtpConnection': EmuWinFtpConnection,
    }

    ObjectTable = {

    }

    ObjectNameTable = {

    }

    ObjectHandleTable = {

    }

    @staticmethod
    def new_handle():
        handle_id = ObjectManager.HANDLE_ID
        ObjectManager.HANDLE_ID += 4

        return handle_id

    @staticmethod
    def new_id():
        _id = ObjectManager.OBJECT_ID
        ObjectManager.OBJECT_ID += 4
        return _id

    @staticmethod
    def new_pid():
        pid = ObjectManager.PROCESS_ID
        ObjectManager.PROCESS_ID += 4
        return pid

    @staticmethod
    def new_tid():
        tid = ObjectManager.THREAD_ID
        ObjectManager.THREAD_ID += 4
        return tid

    @staticmethod
    def get_object_handle(objstring, *args):
        if objstring == 'File':
            path = args[0]
            if path in ObjectManager.ObjectNameTable:
                handle = ObjectManager.new_handle()
                oid = ObjectManager.ObjectNameTable[path]
                ObjectManager.ObjectHandleTable[handle] = oid
                ObjectManager.ObjectTable[oid].inc_refcount()

                return handle
            else:
                new_handle = ObjectManager.create_new_object(objstring, *args)
                ObjectManager.ObjectNameTable[path] = ObjectManager.ObjectHandleTable[new_handle]
        else:
            new_handle = ObjectManager.create_new_object(objstring, args)

        return new_handle


    @staticmethod
    def create_new_object(objstring, *args):    
        obj = ObjectManager.EmuObjectNames[objstring]
        new_obj = obj(*args)
        new_obj.set_oid(ObjectManager.new_id())
        if objstring == 'Process':
            uc_eng = args[0]
            new_obj.set_pid(ObjectManager.new_pid())
            new_obj.set_gdt(EmuGDT(uc_eng)) # actually, this is done by core ntoskrnl
        
        elif objstring == 'Thread':
            new_obj.set_tid(ObjectManager.new_tid())

        handle = ObjectManager.add_object(new_obj)

        return handle
        
    @staticmethod
    def add_object(obj):
        handle = ObjectManager.new_handle()
        ObjectManager.ObjectTable[obj.oid] = obj
        ObjectManager.ObjectHandleTable[handle] = obj.oid
        obj.inc_refcount()

        return handle

    @staticmethod
    def get_obj_by_handle(handle):
        if handle in ObjectManager.ObjectHandleTable:
            oid = ObjectManager.ObjectHandleTable[handle]
            return ObjectManager.ObjectTable[oid]
        else:
            return None
    
    @staticmethod
    def close_handle(handle_id):
        obj = ObjectManager.get_obj_by_handle(handle_id)
        obj.refcount -= 1
        try:
            del ObjectManager.ObjectHandleTable[handle_id]
            if obj.refcount == 0:
                del ObjectManager.ObjectTable[obj.oid]
                if obj.name:
                    del ObjectManager.ObjectNameTable[obj.name]
            return True
        except Exception:
            return False