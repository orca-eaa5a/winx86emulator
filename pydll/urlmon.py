# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from urllib.parse import urlparse

from speakeasy.windows.windows.urlmon import *
from speakeasy.windows.windows.windows import ERROR_SUCCESS
from uc_handler.api_handler import ApiHandler
import common


class Urlmon(ApiHandler):

    name = 'urlmon'
    api_call = ApiHandler.api_call

    def __init__(self, win_emu):
        self.win_emu = win_emu
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
            url = proc.read_string(szURL, cw)
            argv[1] = url
            ps_url = urlparse(url)

        if szFileName:
            name = proc.read_string(szFileName, cw)
            argv[2] = name

        inet_inst_handle = self.win_emu.net_manager.create_inet_inst(agent="Mozilla")
        if ps_url.scheme == "https":
            port = 443
        if ps_url.scheme == "http":
            port = 80

        http_conn_handle = self.win_emu.net_manager.create_connection(
                inet_inst_handle, 
                host=ps_url.netloc,
                port=port
            )
        if not http_conn_handle or http_conn_handle == 0xFFFFFFFF:
            rv = INET_E_DOWNLOAD_FAILURE
        else:
            http_req_handle = self.win_emu.net_manager.create_http_request(
                    http_conn_handle,
                    url
                )
            
            self.win_emu.net_manager.send_http_request(
                http_req_handle,
                None
            )
            rv = ERROR_SUCCESS
            buf = self.win_emu.net_manager.recv_http_response(http_req_handle, 0)
        
        return rv
