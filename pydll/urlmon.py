# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from urllib.parse import urlparse

import speakeasy.winenv.defs.windows.windows as windefs
from cb_handler import ApiHandler
from cb_handler import CALL_CONV as cv
import common


class Urlmon(ApiHandler):

    name = 'urlmon'
    api_call = ApiHandler.api_call

    def __init__(self, emu):
        self.funcs = {}
        self.data = {}
        self.names = {}
        super().__set_api_attrs__(self) # initalize info about each apis

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
        

        cw = common.get_char_width(ctx)

        if szURL:
            url = common.read_mem_string(emu.uc_eng, szURL, cw)
            argv[1] = url
            ps_url = urlparse(url)

        if szFileName:
            name = common.read_mem_string(emu.uc_eng, szFileName, cw)
            argv[2] = name

        inet_inst = emu.net_manager.create_inet(agent="Default")

        http_sess = emu.net_manager.create_connection(
                inet_inst.handle_id, 
                host=ps_url.netloc
            )
        if not http_sess:
            rv = windefs.INET_E_DOWNLOAD_FAILURE
        else:
            http_req = emu.net_manager.create_http_request(
                    http_sess.handle_id,
                    url
                )
            
            emu.net_manager.send_http_request(
                http_req.handle_id,
                None
            )
            rv = windefs.ERROR_SUCCESS
            buf = emu.net_manager.recv_http_response(http_req.handle_id, 0)
        
        return rv
