import http
import ftplib
from urllib.parse import urlparse
from objmanager.emuobj import EmuObject
from netmanager.windefs import InetAccessType, InternetPort, IntertetService, WinHttpFlag, AddressFamily

class EmuWinInetSession(EmuObject):
    def __init__(self, agent, proxy=0,bypass=0, access_types=InetAccessType.INTERNET_OPEN_TYPE_DIRECT, flag=0):
        super().__init__()
        self.agent = agent
        if proxy == 0: # null
            self.proxy = None
        else:
            self.proxy = proxy
        if bypass == 0: # null
            self.bypass= None
        else:
            self.bypass = bypass
        self.access_types = access_types
        self.flag = flag
    

class EmuWinHttpConnection(EmuObject):
    def __init__(self, instance:EmuWinInetSession, host_name, ctx, port=InternetPort.INTERNET_DEFAULT_HTTP_PORT, svc_type=IntertetService.INTERNET_SERVICE_HTTP, flag=0):
        super().__init__()
        self.instance = instance
        self.host_name = host_name
        self.port = port
        self.ctx = ctx
        self.svc_type = svc_type
        self.http_flag=flag
        self.conn = None
        self.connect()
        self.is_ssl = False

# return handle of WinHttpSession or WinFtpSession
    def connect(self):
        import ssl
        if WinHttpFlag.INTERNET_FLAG_SECURE & self.http_flag or self.port == 443:
            self.conn = http.client.HTTPSConnection(
                host=self.host_name,
                timeout=10,
                context=ssl._create_unverified_context(),
            )
            self.is_ssl = True
        else:
            self.conn = http.client.HTTPConnection(
                host=self.host_name,
                port=self.port,
                timeout=10
            )

class EmuWinHttpRequest(EmuObject):
    def __init__(self, instance:EmuWinHttpConnection,  u_path, refer, accept_types=None, verb='GET', version=1.1):
        super().__init__()
        self.conn_instance = instance
        if self.conn_instance.svc_type != IntertetService.INTERNET_SERVICE_HTTP: # <-- maybe ftp
            raise Exception("Service Type is different")
        self.uPath = u_path
        self.verb=verb.lower()
        self.version=version
        self.refer=refer
        self.accept_types = accept_types
        self.header = {}
        self.avaliable_size = 0xFFFFFFFF
        self.resp = None

        if self.accept_types:
            _accept_types = ", ".join(self.accept_types)
            self.add_header("Accept", _accept_types)
                
        if WinHttpFlag.INTERNET_FLAG_DONT_CACHE & self.conn_instance.http_flag:
            self.header["Cache-Control"] = "no-cache"
        if WinHttpFlag.INTERNET_FLAG_FROM_CACHE & self.conn_instance.http_flag:
            self.header["Cache-Control"] = "only-if-cached"
        # if WinHttpFlag.INTERNET_FLAG_IGNORE_CERT_CN_INVALID & self.http_flag: <-- Default
        
    
    def add_header(self, key, value):
        self.header[key] = value

    def add_headers(self, hdrs):
        for key in hdrs.keys():
            self.header[key] = hdrs[key]
        pass

    def set_reqinfo(self):
        self.avaliable_size = self.resp.length

    def send_req(self, data=None):
        if self.verb == 'post':
            self.conn_instance.conn.request(
                method=self.verb.upper(), 
                url=self.uPath,
                headers=self.header,
                body=data)
        else:
            self.conn_instance.conn.request(
                method=self.verb.upper(), 
                url=self.uPath,
                headers=self.header)

        self.resp = self.conn_instance.conn.getresponse()

    def get_resp(self):
        return self.resp

    def send_http_request(self, data:bytes=None, redirect=True):
        def resolve_http_redirect(url, depth=0):
            if depth > 5:
                raise Exception("redirection error")
            o = urlparse(url,allow_fragments=True)
            if o.scheme == "http":
                conn = http.client.HTTPConnection(o.netloc)
            elif o.scheme == "https":
                import ssl
                conn = http.client.HTTPSConnection(host=o.netloc, port=443, context=ssl._create_unverified_context())            
            path = o.path
            if o.query:
                path +='?'+o.query
            conn.request("HEAD", path)
            res = conn.getresponse()
            headers = dict(res.getheaders())
            if "Location" in headers and headers["Location"] != url:
                return resolve_http_redirect(headers['Location'], depth+1)
            else:
                return url

        self.send_req()

        if redirect and ( 300 <= self.resp.status and self.resp.status < 400 ):
            redirected_url = resolve_http_redirect(self.resp.getheader("Location"))
            p_url = urlparse(redirected_url)
            redi_conn = EmuWinHttpConnection(
                        self.conn_instance.instance, 
                        p_url.netloc, 
                        self.conn_instance.ctx, 
                        self.conn_instance.port, 
                        self.conn_instance.svc_type,
                        self.conn_instance.http_flag
                    ) 
            redi_req = EmuWinHttpRequest(
                    redi_conn, 
                    p_url.path, 
                    self.refer,
                    self.accept_types,
                    self.verb,
                    self.version
                )
            
            redi_req.send_req()
            self.change_redirected_resp(redi_req.resp)

        self.set_reqinfo()
        return self.resp

    def recv_http_response(self, recv_size)->bytes:
        if recv_size == 0:
            buf = self.resp.read()
        else:
            buf = self.resp.read(recv_size)
        
        recv_sz = len(buf)
        self.renew_avaliable_size(recv_sz)
        
        return buf

    def change_redirected_resp(self, resp):
        self.resp = resp

    def renew_avaliable_size(self, sz):
        self.avaliable_size -= sz

class EmuWinFtpConnection(EmuObject):
    def __init__(self, instance:EmuWinInetSession, url, usr_name, usr_pwd, ctx, port=InternetPort.INTERNET_DEFAULT_FTP_PORT, svc_type=IntertetService.INTERNET_SERVICE_FTP, flag=0):
        super().__init__()
        self.instance = instance
        self.url = url
        self.port = port
        self.ctx = ctx
        self.uname = usr_name
        self.pwd = usr_pwd
        self.svc_type = svc_type
        
        if self.svc_type != IntertetService.INTERNET_SERVICE_FTP:
            raise Exception("Service Type is different")
        
        self.conn = ftplib.FTP()
        self.conn.connect(self.url, self.port)
        if self.uname == None:
            self.uname = "Anonymous"
            self.pwd = ""
        self.conn.login(self.uname, self.pwd)
    
    def send_cmd(self, cmd):
        res = self.conn.sendcmd(cmd)
        return res
    
    def delete_file(self, filename):
        res = self.conn.delete(filename)
        return res