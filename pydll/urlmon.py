# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from urllib.parse import urlparse

import speakeasy.winenv.defs.windows.windows as windefs
from api_handler import CALL_CONV as cv
from api_handler import ApiHandler
import common


class Urlmon(ApiHandler):

    name = 'urlmon'
    api_call = ApiHandler.api_call

    def __init__(self, emu):

        super(Urlmon, self).__init__(emu)
        self.funcs = {}
        self.data = {}
        super().__get_api_attrs__(self) # initalize info about each apis
        self.netman = emu.get_network_manager()
        self.names = {}

    @api_call('URLDownloadToFile', argc=5)
    def URLDownloadToFile(self, emu, argv, ctx={}):
        """
        HRESULT URLDownloadToFile(
                    LPUNKNOWN            pCaller,
                    LPCTSTR              szURL,
                    LPCTSTR              szFileName,
                    DWORD                dwReserved,
                    LPBINDSTATUSCALLBACK lpfnCB
        );
        """
        pCaller, szURL, szFileName, dwReserved, lpfnCB = argv
        rv = windefs.ERROR_SUCCESS

        cw = common.get_char_width(ctx)

        if szURL:
            url = common.read_mem_string(emu.emu_eng, szURL, cw)
            argv[1] = url
            url = urlparse(url)

        if szFileName:
            name = common.read_mem_string(emu.emu_eng, szFileName, cw)
            argv[2] = name

        inet_inst = emu.net_manager.create_inet(agent="Default")

        http_sess = emu.net_manager.create_connection(
                inet_inst.handle_id, 
                url=url
            )

        http_req = emu.net_manager.create_http_request(
                http_sess.handle_id,
                url,
            )
        
        emu.net_manager.send_http_request(
            http_req.handle_id,
            None
        )

        buf = emu.net_manager.recv_http_response(http_req.handle_id, 0)
        
        return rv
