import sys
import os.path

p = os.path.abspath(os.path.join(__file__, "../..", "fsmanager"))
sys.path.append(p)

import emu_io_layer
import fs_emu_util
