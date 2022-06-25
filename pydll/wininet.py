import socket
from socket import gaierror
import speakeasy.winenv.defs.windows.windows as windefs
from cb_handler import ApiHandler
from cb_handler import CALL_CONV as cv
import common
from urllib.parse import urlparse
import speakeasy_origin.windef.wininet as inet_def
from netmanager.windefs import InetAccessType, InternetPort, IntertetService, EmuWinHttpFlag, AddressFamily

class WinInet(ApiHandler):
    name = "user32"
    api_call = ApiHandler.api_call
    
    def __init__(self, win_emu):
        self.win_emu = win_emu
        self.funcs = {}
        self.data = {}
        self.window_hooks = {}
        self.handle = 0
        self.win = None
        self.handles = []
        self.timer_count = 0
        

        super().__set_api_attrs__(self)

    @api_call('InternetOpen', argc=5)
    def InternetOpen(self, proc, argv, ctx={}):
        """
        void InternetOpenA(
            LPTSTR lpszAgent,
            DWORD  dwAccessType,
            LPTSTR lpszProxy,
            LPTSTR lpszProxyBypass,
            DWORD  dwFlags
        );
        """
        ua, access, proxy, bypass, flags = argv

        cw = common.get_char_width(ctx)
        if ua:
            ua = proc.read_string(ua, cw)
            argv[0] = ua
        if proxy:
            proxy = proc.read_string(proxy, cw)
            argv[2] = proxy
        if bypass:
            bypass = proc.read_string(bypass, cw)
            argv[3] = bypass

        inet_handle = self.win_emu.obj_manager.get_object_handle('WinHttpSession', ua, proxy, bypass)

        return inet_handle

    @api_call('InternetOpenUrl', argc=6)
    def InternetOpenUrl(self, proc, argv, ctx={}):
        """
        void InternetOpenUrlA(
            HINTERNET hInternet,
            LPCSTR    lpszUrl,
            LPCSTR    lpszHeaders,
            DWORD     dwHeadersLength,
            DWORD     dwFlags,
            DWORD_PTR dwContext
        );
        """
        hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext = argv
        cw = ApiHandler.get_char_width(ctx)
        if lpszUrl:
            url = proc.read_string(lpszUrl, cw)
            argv[1] = url
        if lpszHeaders:
            hdrs = {}
            headers = proc.read_string(lpszHeaders, cw)
            _headers = headers.split("\r\n")
            for header in _headers:
                k, v = header.split(":")
                if v[0] == " ":
                    v = v[1:]
                hdrs[k] = v
            argv[2] = headers

        defs = windefs.get_flag_defines(dwFlags)
        argv[4] = ' | '.join(defs)

        crack = urlparse(url)
        if crack.scheme == "http":
            # FIXME : parse port in url netloc
            port = 80
        else:
            port = 443

        sessionInstance = self.win_emu.get_obj_by_handle(hInternet)
        host = crack.netloc

        if port == 80:
            try:
                socket.getaddrinfo(host, 80, AddressFamily.AF_INET)
            except gaierror:
                return 0xFFFFFFFF
        elif port == 443:
            try:
                socket.getaddrinfo(host, 443, AddressFamily.AF_INET)
            except gaierror:
                return 0xFFFFFFFF
        else:
            # TODO : support various web port
            return 0xFFFFFFFF

        hConnection = self.win_emu.obj_manger.get_object_handle(
            'WinHttpConnection', 
            sessionInstance,
            crack.netloc,
            dwFlags,
            dwContext,
            port,
            IntertetService.INTERNET_SERVICE_HTTP,
            dwFlags
        )
        
        connInstance = self.win_emu.obj_manager.get_obj_by_handle(hConnection)
        hRequest = self.win_emu.obj_manager.get_object_handle(
            'WinHttpRequest',
            connInstance,
            crack.path,
            dwFlags
        )

        reqInstance = self.win_emu.obj_manager.get_obj_by_handle(hRequest)
        if hdrs:
            reqInstance.add_headers(hdrs)

        reqInstance.send_http_request(None)        
        
        return hRequest

    @api_call('HttpQueryInfo', argc=5)
    def HttpQueryInfo(self, proc, argv, ctx={}):
        """
        BOOLAPI HttpQueryInfo(
            HINTERNET hRequest,
            DWORD     dwInfoLevel,
            LPVOID    lpBuffer,
            LPDWORD   lpdwBufferLength,
            LPDWORD   lpdwIndex
        );
        """
        hRequest, dwInfoLevel, lpBuffer, lpdwBufferLength, lpdwIndex = argv
        cw = self.get_char_width(ctx)

        rv = False
        if lpBuffer:
            buf_len = proc.read_mem_self(lpdwBufferLength, 4)
            buf_len = int.from_bytes(buf_len, 'little')
        else:
            return False

        reqInstance = self.win_emu.obj_manager.get_obj_by_handle(hRequest)
        info = reqInstance.get_resp()

        if inet_def.HTTP_QUERY_STATUS_CODE == dwInfoLevel:
            if cw == 2:
                enc = 'utf-16le'
            elif cw == 1:
                enc = 'utf-8'
            out = str(info.status).encode(enc)
            if len(out) > buf_len:
                out = out[:buf_len]
            proc.write_mem_self(lpBuffer, out)
            rv = True

        elif inet_def.HTTP_QUERY_CONTENT_LENGTH == dwInfoLevel:
            content_len = info.length
            out = int.to_bytes(content_len, 4, "little")
            proc.write_mem_self(lpBuffer, out)
            proc.write_mem_self(lpdwBufferLength, int.to_bytes(len(out), 4, "little"))
            rv = True

        return rv

    @api_call('InternetQueryDataAvailable', argc=4)
    def InternetQueryDataAvailable(self, proc, argv, ctx={}):
        """
        BOOLAPI InternetQueryDataAvailable(
            HINTERNET hFile, # Handle returned by the InternetOpenUrl, FtpOpenFile, GopherOpenFile, or HttpOpenRequest function.
            LPDWORD   lpdwNumberOfBytesAvailable,
            DWORD     dwFlags,
            DWORD_PTR dwContext
        );
        """
        hFile, lpdwNumberOfBytesAvailable, dwFlags, dwContext = argv
        rv = False

        reqInstance = self.win_emu.obj_manager.get_obj_by_handle(hFile)

        aval = reqInstance.avaliable_size

        if lpdwNumberOfBytesAvailable:
            proc.write_mem_self(lpdwNumberOfBytesAvailable, aval.to_bytes(4, "little"))
            rv = True

        return rv

    @api_call('InternetReadFile', argc=4)
    def InternetReadFile(self, proc, argv, ctx={}):
        """
        BOOLAPI InternetReadFile(
            HINTERNET hFile,
            LPVOID    lpBuffer,
            DWORD     dwNumberOfBytesToRead,
            LPDWORD   lpdwNumberOfBytesRead
        );
        """
        hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead = argv

        rv = 1
        reqInstance = self.win_emu.obj_manager.get_obj_by_handle(hFile)

        buf = reqInstance.recv_http_response(dwNumberOfBytesToRead)
        proc.write_mem_self(lpBuffer, buf)

        if lpdwNumberOfBytesRead:
            proc.write_mem_self(lpdwNumberOfBytesRead, (len(buf)).to_bytes(4, 'little'))

        return rv