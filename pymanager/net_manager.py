from urllib.parse import urlparse
from typing import Dict, List
import http.client
import ftplib
import ssl


from windef.net_defs import InetAccessType, InternetFlag, InternetPort, IntertetService
from windef.net_defs import WinHttpAccessType, WinHttpFlag

def is_empty(byte_buffer):
    if not byte_buffer:
        return True
    return False

class Socket:
    """
    Represents a Windows network socket
    """
    def __init__(self, fd, family, stype, protocol, flags):
        self.fd = fd
        self.family = family
        self.type = stype
        self.protocol = protocol
        self.flags = flags
        self.connected_host = ''
        self.connected_port = 0
        self.curr_packet = b''
        self.packet_queue = []
        self.recv_queue = []

    def get_fd(self):
        return self.fd

    def get_type(self):
        return self.type

    def set_connection_info(self, host, port):
        self.connected_host = host
        self.connected_port = port

    def get_connection_info(self):
        return (self.connected_host, self.connected_port)
        


class WSKSocket(Socket):
    def __init__(self, fd, family, stype, protocol, flags):
        super().__init__(fd, family, stype, protocol, flags)


class WinINetInstance:
    handle_id = 0x100
    def __init__(self, agent, proxy=0,bypass=0, access_types=InetAccessType.INTERNET_OPEN_TYPE_DIRECT, flag=0):
        self.handle_id = 0xFFFFFFFF
        self.agent = agent
        if proxy == 0: # null
            self.proxy = None
        else:
            self.proxy = proxy
        if bypass == 0: # null
            self.proxy = None
        else:
            self.bypass = bypass
        self.access_types = access_types
        self.flag = flag
    
    def create_new_handle(self, handle_id):
        self.handle_id = handle_id

class WinHttpSession(WinINetInstance):
    handle_id = WinINetInstance.handle_id + 0x200
    def __init__(self, instance:WinINetInstance, url, ctx, port=InternetPort.INTERNET_DEFAULT_HTTP_PORT, svc_type=IntertetService.INTERNET_SERVICE_HTTP, flag=0):
        super().__init__(instance.agent, instance.proxy, instance.bypass, instance.access_types, instance.flag)
        self.url = url
        self.port = port
        self.ctx = ctx
        self.instance = instance
        self.svc_type = svc_type

class WinHttpRequest(WinHttpSession):
    handle_id = WinHttpSession.handle_id + 0x300
    def __init__(self, sess:WinHttpSession,  obj_name, refer, flag, ctx, accept_types=None, verb='GET', version=1.1):
        super().__init__(sess.instance, sess.url, sess.ctx, sess.port)
        if self.svc_type != IntertetService.INTERNET_SERVICE_HTTP: # <-- maybe ftp
            raise Exception("Service Type is different")

        self.verb=verb.lower()
        self.obj_name=obj_name
        self.path = None
        self.params = None
        self.query = None
        self.version=version
        self.refer=refer
        self.accept_types:List = accept_types
        self.http_flag=flag
        self.header = {}

        if self.accept_types:
            _accept_types = ", ".join(self.accept_types)
            self.add_header("Accept", _accept_types)
                
        if WinHttpFlag.INTERNET_FLAG_DONT_CACHE & self.http_flag:
            self.header["Cache-Control"] = "no-cache"
        if WinHttpFlag.INTERNET_FLAG_FROM_CACHE & self.http_flag:
            self.header["Cache-Control"] = "only-if-cached"
        # if WinHttpFlag.INTERNET_FLAG_IGNORE_CERT_CN_INVALID & self.http_flag: <-- Default
        
        if WinHttpFlag.INTERNET_FLAG_SECURE & self.http_flag:
            self.port = 443
            self.conn = http.client.HTTPSConnection(
                self.url,
                timeout=10,
                context=ssl._create_unverified_context(),
                
                )
        else:
            self.conn = http.client.HTTPConnection(
                host=self.url,
                port=self.port,
                timeout=10
            )
    
    def add_header(self, key, value):
        self.header[key] = value

    def add_headers(self, hdrs):
        for key in hdrs.keys():
            self.header[key] = hdrs[key]
        pass
    
    def parse_obj(self):
        _p = urlparse(self.obj_name)
        self.path = _p.path
        self.params = _p.params
        self.query = _p.query

class WinFtpSession(WinINetInstance):
    handle_id = WinHttpSession.handle_id
    def __init__(self, instance:WinINetInstance, url, usr_name, usr_pwd, ctx, port=InternetPort.INTERNET_DEFAULT_FTP_PORT, svc_type=IntertetService.INTERNET_SERVICE_FTP, flag=0):
        super().__init__(instance.agent, instance.proxy, instance.bypass, instance.access_types, instance.flag)
        self.url = url
        self.port = port
        self.ctx = ctx
        self.uname = usr_name
        self.pwd = usr_pwd
        self.svc_type = svc_type
        self.instance = instance
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
    
    # Implement like this

        
class NetworkHandleManager:
    def __init__(self):
        self.inet_inst_list=[]
        self.http_sess_list=[]
        self.http_req_list=[]
        self.ftp_sess_list=[]
    
    def get_inet_inst_by_handle(self, handle_id):
        for inet_inst in self.inet_inst_list:
            if inet_inst.handle_id == handle_id:
                return inet_inst
        return None

    def get_http_sess_by_handle(self, handle_id):
        for http_sess in self.http_sess_list:
            if http_sess.handle_id == handle_id:
                return http_sess
        return None

    def get_http_req_by_handle(self, handle_id):
        for http_req in self.http_req_list:
            if http_req.handle_id == handle_id:
                return http_req
        return None

    def get_obj_by_handle(self, handle_id):
        obj = self.get_inet_inst_by_handle(handle_id)
        if obj:
            return obj
        obj = self.get_http_sess_by_handle(handle_id)
        if obj:
            return obj
        obj = self.get_http_req_by_handle(handle_id)
        if obj:
            return obj
        raise Exception("Invalid handle")

    def delete_inet_inst_by_handle(self, handle_id):
        obj = self.get_inet_inst_by_handle(handle_id)
        if obj:
            self.inet_inst_list.remove(obj)
            return True
        return False
    
    def delete_http_sess_by_handle(self, handle_id):
        obj = self.get_http_sess_by_handle(handle_id)
        if obj:
            self.http_sess_list.remove(obj)
            return True
        return False
    
    def delete_http_req_by_handle(self, handle_id):
        obj = self.get_http_req_by_handle(handle_id)
        if obj:
            self.http_req_list.remove(obj)
            return True
        return False

    def create_inet_instance_handle(self, agent, proxy=0,bypass=0, access_types=InetAccessType.INTERNET_OPEN_TYPE_DIRECT, flag=0):
        win_inet_inst = WinINetInstance(agent=agent, proxy=proxy, bypass=bypass, access_types=access_types, flag=flag)
        win_inet_inst.create_new_handle(WinINetInstance.handle_id)
        WinINetInstance.handle_id+=4
        self.inet_inst_list.append(win_inet_inst)
        
        return win_inet_inst

    def create_http_sess_handle(self, h_internet, url, ctx, port=InternetPort.INTERNET_DEFAULT_HTTP_PORT, svc_type=IntertetService.INTERNET_SERVICE_HTTP, flag=0):
        obj = self.get_inet_inst_by_handle(handle_id=h_internet)
        if not obj:
            raise Exception("Invalid handle")
        win_http_sess = WinHttpSession(obj, url=url, ctx=ctx, port=port, svc_type=svc_type, flag=flag)
        win_http_sess.create_new_handle(WinHttpSession.handle_id)
        WinHttpSession.handle_id += 4
        self.http_sess_list.append(win_http_sess)

        return win_http_sess

    def create_ftp_sess_handle(self, h_internet, url, usr_name, usr_pwd, ctx, port=InternetPort.INTERNET_DEFAULT_FTP_PORT, svc_type=IntertetService.INTERNET_SERVICE_FTP, flag=0):
        obj = self.get_inet_inst_by_handle(handle_id=h_internet)
        if not obj:
            raise Exception("Invalid handle")
        ftp_sess = WinFtpSession(obj, url, usr_name, usr_pwd, ctx)
        ftp_sess.create_new_handle(WinFtpSession.handle_id)
        WinFtpSession.handle_id += 4
        self.ftp_sess_list.append(ftp_sess)

        return ftp_sess

    def create_http_req_handle(self, h_connect, obj_name, refer, flag, ctx, accept_types=None, verb='GET', version=1.1):
        obj = self.get_http_sess_by_handle(handle_id=h_connect)
        if not obj:
            raise Exception("Invalid handle")
        win_http_req = WinHttpRequest(obj, obj_name, refer, flag, ctx, accept_types, verb, version)
        win_http_req.create_new_handle(WinHttpRequest.handle_id)
        WinHttpRequest.handle_id+=4
        self.http_req_list.append(win_http_req)

        return win_http_req

    def close_handle(self, handle_id):
        if self.delete_inet_inst_by_handle(handle_id):
            return True
        if self.delete_http_sess_by_handle(handle_id):
            return True
        if self.delete_http_req_by_handle(handle_id):
            return True
        return False

class NetworkManager:
    def __init__(self):
        self.net_handle_manager=NetworkHandleManager()
        self.req_queue = []

    def create_inet(self, agent, proxy=0,bypass=0, access_types=InetAccessType.INTERNET_OPEN_TYPE_DIRECT, flag=0):
        # Respond with
        # HINTERNET InternetOpen 
        inet_inst = self.net_handle_manager.create_inet_instance_handle(agent, proxy, bypass, access_types, flag)

        return inet_inst

    def create_connection(self, inst_handle, url, usr_name, usr_pwd, ctx, port, svc_type, flag=0):
        # Respond with
        # HCONNECT InternetConnect
        if IntertetService.INTERNET_SERVICE_FTP:
            conn = self.net_handle_manager.create_ftp_sess_handle(inst_handle, url, usr_name, usr_pwd, ctx, port, svc_type, flag)
        elif IntertetService.INTERNET_SERVICE_HTTP:
            conn = self.net_handle_manager.create_http_sess_handle(inst_handle, url, ctx, port, svc_type, flag)
        else:
            raise Exception("Not supported in this emulation")

        return conn

    def create_http_request(self, conn_handle, obj_name, refer, flag, ctx, accept_types=None, verb='GET', version=1.1):
        # Respond with
        # HANDLE OpenHttpRequest
        http_req = self.net_handle_manager.create_http_req_handle(conn_handle, obj_name, refer, flag, ctx, accept_types, verb, version)
        
        return http_req

    def send_http_request(self, handle_id, data:bytes):
        http_request:WinHttpRequest = self.net_handle_manager.get_http_req_by_handle(handle_id)
        if http_request.verb == 'post':
            http_request.conn.request(
                method=http_request.verb.upper(), 
                url=http_request.obj_name,
                headers=http_request.header,
                body=data)
        else:
            http_request.conn.request(
                method=http_request.verb.upper(), 
                url=http_request.obj_name,
                headers=http_request.header)
        
        self.req_queue.append({
            "handle_id": http_request.handle_id,
            "resp": http_request.conn.getresponse() # <-- http stream
        })
    
    def recv_http_response(self, handle_id, recv_size)->bytes:
        http_req = None
        idx = 0
        for req in self.req_queue:
            if req["handle_id"] == handle_id:
                http_req = self.req_queue.pop(idx)
                break
            idx+=1
        if http_req == None:
            raise Exception("Responded handle has no http request")
        
        buf = http_req.read(recv_size)
        if len(buf) >= recv_size:
            self.req_queue.append(http_req)
        
        return buf
            


