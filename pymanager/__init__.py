import sys
import os.path
__all__ = [
    "fsmanager",
    "objmanager"
]

for package in __all__:
    p = os.path.abspath(os.path.join(__file__, ".."))
    sys.path.append(p)
