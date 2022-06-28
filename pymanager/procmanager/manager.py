from objmanager.coreobj import EmuProcess, EmuThread
from unicorn.unicorn_const import UC_HOOK_CODE
from pyemulator import ApiHandler

class EmuThreadManager:
    # Thread는 하나의 Unicorn Engine 위에서 동작
    # Unicorn Engine은 Multi-Threading을 지원하지 않으므로 EmuThread는 한 번에 하나씩 실행
    # Thread 시작점 : resume_thread
    # 새로 생성된 Thread는 wait_queue에 들어감
    running_thread = {}
    wait_thread_q = {}
    ctx_switch_processing = False
    
    @staticmethod
    def context_switch_cb(proc_obj:EmuProcess):
        """_summary_
            Switch currently running uc_eng context
        Args:
            proc_obj (EmuProcess): Process which is current running
        """
        proc_obj.running_thread.save_context()
        EmuThreadManager.push_wait_queue(proc_obj.pid, proc_obj.running_thread.tid, proc_obj.running_thread)
        # rt = EmuThreadManager.deq_wait_queue(proc_obj.pid)
        # EmuThreadManager.set_ready_thread(proc_obj.pid, rt["tid"], rt["obj"])
        EmuThreadManager.ctx_switch_processing = True
        proc_obj.running_thread = None
        
        
    @staticmethod
    def context_switch(proc_obj:EmuProcess):
        proc_obj.uc_eng.hook_add(UC_HOOK_CODE, ApiHandler.post_api_call_cb_wrapper, (proc_obj, (proc_obj), 1, EmuThreadManager.context_switch_cb))

    @staticmethod
    def set_running_thread(pid:int, tid:int, obj:EmuThread):
        EmuThreadManager.running_thread[pid] = {
            "tid": tid,
            "obj": obj
        }

    @staticmethod
    def push_wait_queue(pid:int, tid:int, obj:EmuThread):
        if pid not in EmuThreadManager.wait_thread_q:
            EmuThreadManager.wait_thread_q[pid] = []
        EmuThreadManager.wait_thread_q[pid].append({
            "tid": tid,
            "obj": obj
        })

    @staticmethod
    def deq_wait_queue(pid, idx=0):
        if pid not in EmuThreadManager.wait_thread_q:
            return None
        return EmuThreadManager.wait_thread_q[pid].pop(idx)

    @staticmethod
    def get_wait_queue(pid):
        if pid in EmuThreadManager.wait_thread_q:
            return EmuThreadManager.wait_thread_q[pid]
        return None

    def __init__(self) -> None:
        pass

class EmuProcManager:
    # Scheduling Process
    running_proc_q = []
    wait_proc_q = []

    @staticmethod
    def is_wait_empty():
        if len(EmuProcManager.wait_proc_q) == 0:
            return True
        return False

    @staticmethod
    def push_running_queue(pid:int, obj:EmuProcess):
        EmuProcManager.running_proc_q.append({
            "pid": pid,
            "obj": obj
        })
        pass
    @staticmethod
    def push_wait_queue(pid:int, obj:EmuProcess):
        EmuProcManager.wait_proc_q.append({
            "pid": pid,
            "obj": obj
        })
        pass

    @staticmethod
    def deq_wait_queue():
        return EmuProcManager.wait_proc_q.pop(0)

    def __init__(self) -> None:
        pass