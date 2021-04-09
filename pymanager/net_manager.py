from urllib.parse import urlparse
from typing import Dict, List
import http.client
import ftplib
import socket
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
            self.bypass= None
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
        url = urlparse(self.url)

        self.url = url.hostname
        if obj_name:
            self.obj_name=obj_name
        else:
            self.obj_name=url.path
        self.scheme = url.scheme
        self.verb=verb.lower()
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
        
        if WinHttpFlag.INTERNET_FLAG_SECURE & self.http_flag or self.scheme == "https":
            self.port = 443
            self.conn = http.client.HTTPSConnection(
                host=self.url,
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
        self.socket_list=[]
    
    def get_inet_inst_by_handle(self, handle_id)->WinINetInstance:
        for inet_inst in self.inet_inst_list:
            if inet_inst.handle_id == handle_id:
                return inet_inst
        return None

    def get_http_sess_by_handle(self, handle_id)->WinHttpSession:
        for http_sess in self.http_sess_list:
            if http_sess.handle_id == handle_id:
                return http_sess
        return None

    def get_http_req_by_handle(self, handle_id)->WinHttpRequest:
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

    def create_inet_instance_handle(self, agent, proxy=0,bypass=0,
                                    access_types=InetAccessType.INTERNET_OPEN_TYPE_DIRECT,
                                    flag=0)->WinINetInstance:
        win_inet_inst = WinINetInstance(agent=agent, proxy=proxy, bypass=bypass, access_types=access_types, flag=flag)
        win_inet_inst.create_new_handle(WinINetInstance.handle_id)
        WinINetInstance.handle_id+=4
        self.inet_inst_list.append(win_inet_inst)
        
        return win_inet_inst

    def create_http_sess_handle(self, h_internet, url, ctx, 
                                port=InternetPort.INTERNET_DEFAULT_HTTP_PORT, 
                                svc_type=IntertetService.INTERNET_SERVICE_HTTP, flag=0)->WinHttpSession:
        obj = self.get_inet_inst_by_handle(handle_id=h_internet)
        if not obj:
            raise Exception("Invalid handle")
        url_obj = urlparse(url)

        if url_obj.scheme == "https":
            port = InternetPort.INTERNET_DEFAULT_HTTPS_PORT
        
        win_http_sess = WinHttpSession(obj, url=url, ctx=ctx, port=port, svc_type=svc_type, flag=flag)
        win_http_sess.create_new_handle(WinHttpSession.handle_id)
        WinHttpSession.handle_id += 4
        self.http_sess_list.append(win_http_sess)

        return win_http_sess

    def create_ftp_sess_handle(self, h_internet, url, usr_name, usr_pwd, ctx, 
                                port=InternetPort.INTERNET_DEFAULT_FTP_PORT, 
                                svc_type=IntertetService.INTERNET_SERVICE_FTP, flag=0)->WinFtpSession:
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
        Socket.SOCKET-=4
        pass

    def close_http_handle(self, handle_id):
        if self.delete_inet_inst_by_handle(handle_id):
            WinINetInstance.handle_id-=4
            return True
        if self.delete_http_sess_by_handle(handle_id):
            WinHttpSession.handle_id-=4
            return True
        if self.delete_http_req_by_handle(handle_id):
            WinHttpRequest.handle_id-=4
            return True
        return False

class NetworkManager:
    def __init__(self):
        self.net_handle_manager=NetworkHandleManager()
        self.req_queue = []

    def push_http_request_queue(self, http_req):
        # http_req = {
        #   "handle_id": integer,
        #   "resp": HttpResponse
        # }
        self.req_queue.append(http_req)
        pass

    def get_http_req_by_handle(self, handle_id)->Dict:
        http_req = None
        idx = 0
        for req in self.req_queue:
            if req["handle_id"] == handle_id:
                http_req = self.req_queue.pop(idx)
                break
            idx+=1

        if http_req == None:
            raise Exception("Responded handle has no http request")

        return http_req

    def get_http_resp(self, handle_id, size)->bytes:
        http_req = self.get_http_req_by_handle(handle_id)

        return http_req["resp"].read(size)
        
    def create_inet(self, 
                    agent, 
                    proxy=0, bypass=0, 
                    access_types=InetAccessType.INTERNET_OPEN_TYPE_DIRECT, flag=0)->WinINetInstance:
        # Respond with
        # HINTERNET InternetOpen 
        inet_inst = self.net_handle_manager.create_inet_instance_handle(agent, proxy, bypass, access_types, flag)

        return inet_inst

    def create_connection(  self, 
                            inst_handle, 
                            url, 
                            usr_name=None, 
                            usr_pwd=None, 
                            ctx={}, 
                            port=InternetPort.INTERNET_DEFAULT_HTTP_PORT, 
                            svc_type=IntertetService.INTERNET_SERVICE_HTTP, 
                            flag=0
                        ):
        # Respond with
        # HCONNECT InternetConnect
        if svc_type == IntertetService.INTERNET_SERVICE_FTP:
            conn = self.net_handle_manager.create_ftp_sess_handle(inst_handle, url, usr_name, usr_pwd, ctx, port, svc_type, flag)
        elif svc_type == IntertetService.INTERNET_SERVICE_HTTP:
            conn = self.net_handle_manager.create_http_sess_handle(inst_handle, url, ctx, port, svc_type, flag)
        else:
            raise Exception("Not supported in this emulation")

        return conn # return WinHttpSession or WinFtpSession

    def create_http_request(self, 
                            conn_handle,
                            obj_name, 
                            refer=None, 
                            flag=0, 
                            ctx={}, 
                            accept_types=None, 
                            verb='GET', 
                            version=1.1)->WinHttpRequest:
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
        
        http_req = {
            "handle_id": http_request.handle_id,
            "resp": http_request.conn.getresponse() # <-- http stream
        }
        self.push_http_request_queue(http_req)

        pass
    
    def recv_http_response(self, handle_id, recv_size)->bytes:
        http_req = self.get_http_req_by_handle(handle_id)
        if recv_size == 0:
            buf = http_req["resp"].read()
        else:
            buf = http_req["resp"].read(recv_size)


        if len(buf) >= recv_size and recv_size != 0:
            self.push_http_request_queue(http_req)
        
        return buf

    def get_request_content_length(self, handle_id):
        http_req = self.get_http_req_by_handle(handle_id)
        import copy
        http_resp_cp = copy.deepcopy(http_req["resp"])
        buf = http_resp_cp.read()
        sz = len(buf)
        del buf

        return sz

    def close_http_handle(self, handle_id):
        http_obj = self.net_handle_manager.get_obj_by_handle(handle_id)
        if isinstance(http_obj, WinHttpRequest):
            http_obj.conn.close()
        self.net_handle_manager.close_http_handle(handle_id)
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
