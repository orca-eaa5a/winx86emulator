import os
import ntpath
import string
import fnmatch
import datetime
import ctypes as ct

from api_handler import ApiHandler

import speakeasy.common as common
import speakeasy.winenv.defs.windows.windows as windefs
import speakeasy.winenv.defs.windows.kernel32 as k32types

from .. import api
import common

PAGE_SIZE = 0x1000

class Kernel32(api.ApiHandler):
    """
    Implements exported functions from kernel32.dll
    """
    name = 'kernel32'
    apihook = ApiHandler.apihook
    impdata = ApiHandler.impdata

    def __init__(self, emu):

        super(Kernel32, self).__init__(emu)

        self.funcs = {}
        self.data = {}

        self.heaps = []
        self.curr_handle = 0x1800
        self.find_files = {}
        self.find_volumes = {}
        self.snapshots = {}
        self.find_resources = {}
        self.tick_counter = 86400000  # 1 day in millisecs
        self.perf_counter = 0x5fd27d571f

        self.command_lines = [None] * 3
        self.startup_info = {}

        self.k32types = k32types

        super(Kernel32, self).__get_hook_attrs__(self)

    @apihook('GetSystemTimeAsFileTime', argc=1)
    def GetSystemTimeAsFileTime(self, emu, argv, ctx={}):
        '''void GetSystemTimeAsFileTime(
        LPFILETIME lpSystemTimeAsFileTime
        );'''

        lpSystemTimeAsFileTime, = argv
        ft = self.k32types.FILETIME(emu.get_ptr_size())

        timestamp = 116444736000000000 + int(datetime.datetime.utcnow().timestamp()) * 10000000
        ft.dwLowDateTime = 0xFFFFFFFF & timestamp
        ft.dwHighDateTime = timestamp >> 32

        self.emu.mem_write(lpSystemTimeAsFileTime, )
        self.mem_write(lpSystemTimeAsFileTime, common.get_bytes(ft))

        return