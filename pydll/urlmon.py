# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from urllib.parse import urlparse

import speakeasy.winenv.defs.windows.windows as windefs
from cb_handler import ApiHandler
from cb_handler import CALL_CONV as cv
import common


class Urlmon(ApiHandler):

    name = 'urlmon'
    api_call = ApiHandler.api_call

    def __init__(self):
        self.funcs = {}
        self.data = {}
        self.names = {}
        super().__set_api_attrs__(self) # initalize info about each apis

    @api_call('URLDownloadToFile', argc=5)
    def URLDownloadToFile(self, proc, argv, ctx={}):
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
            url = common.read_mem_string(proc.uc_eng, szURL, cw)
            argv[1] = url
            ps_url = urlparse(url)

        if szFileName:
            name = common.read_mem_string(proc.uc_eng, szFileName, cw)
            argv[2] = name

        inet_inst_handle = proc.emu.net_manager.create_inet_inst(agent="Default")

        if ps_url.scheme == "https":
            port = 443
        if ps_url.scheme == "http":
            port = 80

        http_conn_handle = proc.emu.net_manager.create_connection(
                inet_inst_handle, 
                host=ps_url.netloc,
                port=port
            )
        if not http_conn_handle or http_conn_handle == 0xFFFFFFFF:
            rv = windefs.INET_E_DOWNLOAD_FAILURE
        else:
            http_req_handle = proc.emu.net_manager.create_http_request(
                    http_conn_handle,
                    url
                )
            
            proc.emu.net_manager.send_http_request(
                http_req_handle,
                None
            )
            rv = windefs.ERROR_SUCCESS
            buf = proc.emu.net_manager.recv_http_response(http_req_handle, 0)
        
        return rv
