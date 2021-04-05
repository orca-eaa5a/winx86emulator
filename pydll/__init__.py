import os

__all__ = []

EMULATED_DLL_LIST=[]
SYSTEM_DLL_BASE={}
ALLOCATION_GRANULARITY=0x10000
DLL_BASE = 0x75550000

dirname = os.path.dirname(__file__)
for entry in os.listdir(dirname):
    if os.path.isfile(os.path.join(dirname, entry)):
        base, ext = os.path.splitext(entry)
        if base not in ('__init__', '__dll_dels__') and ext == '.py':
            __all__.append(base)
            EMULATED_DLL_LIST.append(base)

del os

for idx in range(len(EMULATED_DLL_LIST)):
    SYSTEM_DLL_BASE[EMULATED_DLL_LIST[idx]] = DLL_BASE + ALLOCATION_GRANULARITY*idx

