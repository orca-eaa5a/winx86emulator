import importlib
from speakeasy_origin.windef.winsock.winsock import AF_INET
from urllib.parse import urlparse
import urllib.request as request
from typing import Dict, List
import http.client
import ftplib
import socket
from socket import gaierror
import ssl


from pymanager.defs.net_defs import InetAccessType, InternetFlag, InternetPort, IntertetService
from pymanager.defs.net_defs import WinHttpAccessType, WinHttpFlag
from pymanager.defs.net_defs import AddressFamily, WSAFlag, Protocol, SocketType

def is_empty(byte_buffer):
    if not byte_buffer:
        return True
    return False

class Socket:
    SOCKET=0x19190 # unsigned int
    def __init__(self, s, obj):
        self.s = s # unsigned int
        self.pysock = obj
        self.family = obj.family
        self.stype = obj.type
        self.host = ''
        self.port = 0
        self.server_sock_flag=False
        self.curr_packet = b''
        self.packet_queue = []
        self.recv_queue = []

    def get_socket(self):
        return self.s

    def get_type(self):
        return self.stype

    def get_connection_info(self): 
        return (self.host, self.port)

    def set_conn_info(self, host, port):
        self.host = host
        self.port = port
        
    def set_server_flag(self):
        self.server_sock_flag = True

    def set_python_sock(self, s:socket.socket):
        pass

class WSKSocket(Socket):
    SOCKET=Socket.SOCKET
    def __init__(self, s, obj, family, stype, protocol, flag):
        super().__init__(s, obj)
        self.family = family
        self.stype = stype
        self.protocol = protocol
        self.flag = flag

class WinInetObject(object):
    handle_id = 0x100
    def __init__(self) -> None:
        super().__init__()

    def get_handle(self):
        WinInetObject.handle_id += 4

        return WinInetObject.handle_id

class WinINETInstance(WinInetObject):
    def __init__(self, agent, proxy=0,bypass=0, access_types=InetAccessType.INTERNET_OPEN_TYPE_DIRECT, flag=0):
        super().__init__()
        self.handle_id = self.get_handle()
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
    

class WinHttpConnection(WinInetObject):
    def __init__(self, instance:WinINETInstance, host_name, ctx, port=InternetPort.INTERNET_DEFAULT_HTTP_PORT, svc_type=IntertetService.INTERNET_SERVICE_HTTP, flag=0):
        super().__init__()
        self.handle_id = self.get_handle()
        self.instance = instance
        self.host_name = host_name
        self.port = port
        self.ctx = ctx
        self.svc_type = svc_type
        self.http_flag=flag
        self.conn = None
        self.connect()

    def connect(self):
        if WinHttpFlag.INTERNET_FLAG_SECURE & self.http_flag or self.port == 443:
            self.conn = http.client.HTTPSConnection(
                host=self.host_name,
                timeout=10,
                context=ssl._create_unverified_context(),
            )
        else:
            self.conn = http.client.HTTPConnection(
                host=self.host_name,
                port=self.port,
                timeout=10
            )

class WinHttpRequest(WinInetObject):
    def __init__(self, instance:WinHttpConnection,  u_path, refer, accept_types=None, verb='GET', version=1.1):
        super().__init__()
        self.handle_id = self.get_handle()
        self.conn_instance = instance
        if self.conn_instance.svc_type != IntertetService.INTERNET_SERVICE_HTTP: # <-- maybe ftp
            raise Exception("Service Type is different")
        self.uPath = u_path
        self.verb=verb.lower()
        self.version=version
        self.refer=refer
        self.accept_types:List = accept_types
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

    def renew_avaliable_size(self, sz):
        self.avaliable_size -= sz

class WinFtpConnection(WinInetObject):
    
    def __init__(self, instance:WinINETInstance, url, usr_name, usr_pwd, ctx, port=InternetPort.INTERNET_DEFAULT_FTP_PORT, svc_type=IntertetService.INTERNET_SERVICE_FTP, flag=0):
        super().__init__()
        self.handle_id = self.get_handle()
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
    
    # Implement like this

        
class NetworkHandleManager:
    def __init__(self):
        self.win_obj_dict = {}
        self.ftp_sess_list=[]
        self.socket_list=[]
    

    def get_obj_by_handle(self, handle_id):
        if handle_id in self.win_obj_dict:
            return self.win_obj_dict[handle_id]
        return None

    def chage_obj_from_handle(self, handle_id, obj):
        if handle_id in self.win_obj_dict:
            self.win_obj_dict[handle_id] = obj
        else:
            raise Exception("Invalid Handle")
        pass


    def create_inet_obj_handle(self, obj)->WinInetObject:      
        self.win_obj_dict[obj.handle_id] = obj
        
        return obj.handle_id


    def get_socket_by_descripter(self, s)->Socket:
        for sock in self.socket_list:
            if sock.s == s:
                return sock
        raise Exception("Invalid socket descripter")

    def create_sock_descripter(self, pysock)->Socket:
        #SOCKET WSAAPI socket(
        #  int af,
        #  int type,
        #  int protocol
        #);
        s = Socket.SOCKET
        Socket.SOCKET+=4
        sock = Socket(s, pysock)
        self.socket_list.append(sock)

        return sock

    def close_socket(self, s):
        for sock in self.socket_list:
            if sock.s == s:
                self.sock_list.remove(sock)
                break
        pass


class NetworkManager:
    def __init__(self):
        self.net_handle_manager=NetworkHandleManager()
        
    def create_inet_inst(self, 
                    agent, 
                    proxy=0, bypass=0, 
                    access_types=InetAccessType.INTERNET_OPEN_TYPE_DIRECT, 
                    flag=0,
                    raw=False)->WinINETInstance:
        # Respond with
        # HINTERNET InternetOpen
        inet_inst = WinINETInstance(agent, proxy, bypass, access_types, flag)
        if not raw:
            handle_id = self.net_handle_manager.create_inet_obj_handle(inet_inst)

        return inet_inst

    def create_connection(  self, 
                            inst_handle, 
                            host, 
                            usr_name=None, 
                            usr_pwd=None, 
                            ctx={}, 
                            port=InternetPort.INTERNET_DEFAULT_HTTP_PORT, 
                            svc_type=IntertetService.INTERNET_SERVICE_HTTP, 
                            flag=0,
                            raw=False
                        ):
        # Respond with
        # HCONNECT InternetConnect
        if not raw:
            inet_inst = self.net_handle_manager.get_obj_by_handle(inst_handle)
        if not inet_inst:
            raise Exception("Invalid Handle")
        if not isinstance(inet_inst, WinINETInstance):
            raise Exception("Invalid Object Type")

        if svc_type == IntertetService.INTERNET_SERVICE_FTP:
            try:
                socket.getaddrinfo(host, 21, AF_INET)
            except gaierror:
                return None
            conn = WinFtpConnection(inet_inst, host, usr_name, usr_pwd, ctx, port, svc_type, flag)
        
        elif svc_type == IntertetService.INTERNET_SERVICE_HTTP:
            if port == 80:
                try:
                    socket.getaddrinfo(host, 80, AF_INET)
                except gaierror:
                    return None
            elif port == 443:
                try:
                    socket.getaddrinfo(host, 443, AF_INET)
                except gaierror:
                    return None
            else:
                return None            
            conn = WinHttpConnection(inet_inst, host, ctx, port, svc_type, flag)            
        else:
            raise Exception("Not supported in this emulation")

        handle_id = self.net_handle_manager.create_inet_obj_handle(conn)

        return conn # return WinHttpSession or WinFtpSession

    def create_http_request(self, 
                            conn_handle,
                            obj_name, 
                            refer=None, 
                            flag=0, 
                            ctx={}, 
                            accept_types=None, 
                            verb='GET', 
                            version=1.1,
                            raw=False)->WinHttpRequest:
        # Respond with
        # HANDLE OpenHttpRequest
        inet_conn = self.get_obj_by_handle(conn_handle)
        if not inet_conn:
            raise Exception("Invalid Handle")
        if not isinstance(inet_conn, WinHttpConnection):
            raise Exception("Invalid Object Type")

        http_req = WinHttpRequest(inet_conn, obj_name, refer, accept_types, verb, version)
        if not raw:
            handle_id = self.net_handle_manager.create_inet_obj_handle(http_req)
        
        return http_req

    def send_http_request(self, handle_id, data:bytes=None, redirect=True):
        inet_req = self.get_obj_by_handle(handle_id)
        if not inet_req:
            raise Exception("Invalid Handle")
        if not isinstance(inet_req, WinHttpRequest):
            raise Exception("Invalid Object Type")

        inet_req.send_req()
        resp = inet_req.resp

        if redirect:
            for i in range(5):
                inet_inst = inet_req.conn_instance.instance
                next_url = resp.getheader("Location")
                p_url = urlparse(next_url)
                next_conn =  WinHttpConnection(
                        inet_inst, 
                        p_url.netloc, 
                        inet_req.conn_instance.ctx, 
                        inet_req.conn_instance.port, 
                        inet_req.conn_instance.svc_type,
                        inet_req.conn_instance.http_flag
                    )            
                next_req = WinHttpRequest(
                    next_conn, 
                    p_url.path, 
                    inet_req.refer,
                    inet_req.accept_types,
                    inet_req.verb,
                    inet_req.version
                )
                next_req.send_req()
                if next_req.resp.status not in (301, 302):
                    inet_req = next_req
                    resp = inet_req.resp
                    inet_req.handle_id = handle_id
                    self.net_handle_manager.chage_obj_from_handle(handle_id, next_req)
                    break

        inet_req.set_reqinfo()
        return resp
    
    def recv_http_response(self, handle_id, recv_size)->bytes:
        http_req = self.get_obj_by_handle(handle_id)
        if recv_size == 0:
            buf = http_req.resp.read()
        else:
            buf = http_req.resp.read(recv_size)
        
        recv_sz = len(buf)
        http_req.renew_avaliable_size(recv_sz)
        
        return buf

    def get_resp(self, handle_id):
        inet_req = self.get_obj_by_handle(handle_id)
        if not inet_req:
            raise Exception("Invalid Handle")
        if not isinstance(inet_req, WinHttpRequest):
            raise Exception("Invalid Object Type")

        return inet_req.resp

    def get_obj_by_handle(self, handle_id):
        http_obj = self.net_handle_manager.get_obj_by_handle(handle_id)
        return http_obj

    def close_http_handle(self, handle_id):
        http_obj = self.net_handle_manager.get_obj_by_handle(handle_id)
        if isinstance(http_obj, WinHttpRequest):
            http_obj.conn_instance.conn.close()
    
        pass

    def create_socket(self, af, stype, protocol):
        if af == AddressFamily.AF_INET:
            af = socket.AF_INET
        else:
            raise Exception("Unsupport network type")
        if stype == SocketType.SOCK_STREAM and protocol == Protocol.IPPROTO_TCP:
            stype = socket.SOCK_STREAM
        elif stype == SocketType.SOCK_DGRAM and protocol == Protocol.IPPROTO_UDP:
            stype = socket.SOCK_DGRAM
        else:
            raise Exception("Unsupport protocol")
        pysock = socket.socket(af, stype)
        sock = self.net_handle_manager.create_sock_descripter(pysock)
        return sock

    def close_socket(self, s):
        sock = self.net_handle_manager.get_socket_by_descripter(s)
        sock.pysock
        self.net_handle_manager.close_socket(s)
        pass

    def bind_socket(self, s, addr, port):
        #int bind(
        #  __in  SOCKET s,
        #  __in  const struct sockaddr *name,
        #  __in  int namelen
        #);
        
        #struct sockaddr_in {
        #   short   sin_family;
        #   u_short sin_port;
        #   struct  in_addr sin_addr;
        #   char    sin_zero[8];
        #};
        sock = self.net_handle_manager.get_socket_by_descripter(s)
        try:
            sock.pysock.bind(addr, port)
        except Exception as e:
            return False
        sock.set_server_flag()
        return True

    def listen_socket(self, s, backlog):
        sock = self.net_handle_manager.get_socket_by_descripter(s)
        try:
            sock.pysock.listen(backlog)
        except Exception as e:
            return False
        return True
    
    def connect_sock(self, s, host, port):
        sock = self.net_handle_manager.get_socket_by_descripter(s)
        sock.set_conn_info(host, port)
        try:
            sock.pysock.connect(host, port)
        except Exception as e:
            return False
        return True

    def accept_sock(self, s)->Socket:
        sock = self.net_handle_manager.get_socket_by_descripter(s)
        py_c_sock, addr = sock.pysock.accept() # only support block socket
        sock = self.net_handle_manager.create_sock_descripter(pysock)
        sock.set_conn_info(addr)

        return sock
    
    def sock_send(self, s, data)->int:
        sock = self.net_handle_manager.get_socket_by_descripter(s)
        numberOfBytesSent = sock.pysock.send(data)

        return numberOfBytesSent
    
    def sock_recv(self, s, sz)->bytes:
        sock = self.net_handle_manager.get_socket_by_descripter(s)
        data = sock.pysock.recv(sz)

        return data
