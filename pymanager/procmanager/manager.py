from objmanager.coreobj import EmuProcess
from unicorn.unicorn import Uc

class EmuThreadManager:
    def __init__(self) -> None:
        pass

class EmuProcManager:
    # Scheduling Process
    def __init__(self) -> None:
        self.running_proc_q = []
        self.wait_proc_q = []
        pass
    
    def push_running_queue(self, pid:int, obj:EmuProcess):
        self.running_proc_q.append({
            "pid": pid,
            "obj": obj
        })
        pass

    def push_wait_proc(self, pid:int, obj:EmuProcess):
        self.wait_proc_q.append({
            "pid": pid,
            "obj": obj
        })
        pass
    
    def create_process(self, appstr):
