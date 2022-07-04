import http.client

from speakeasy.windows.winsock.winsock import AF_INET
import socket
from socket import gaierror
from urllib.parse import urlparse

from pymanager.objmanager import manager as obj_manager
from pymanager.objmanager.inetobj import EmuWinFtpConnection, EmuWinHttpConnection, EmuWinHttpRequest, EmuWinInetSession
from windefs import InetAccessType, InternetFlag, InternetPort, IntertetService


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
    

class NetworkManager:
    def __init__(self):
        pass
    def create_inet_inst(self, 
                    agent, 
                    proxy=0, bypass=0, 
                    access_types=InetAccessType.INTERNET_OPEN_TYPE_DIRECT, 
                    flag=0,
                    raw=False)->EmuWinInetSession:
        # Respond with
        # HINTERNET InternetOpen
        inet_handle = obj_manager.ObjectManager.create_new_object(EmuWinInetSession, agent, proxy, bypass, access_types, flag)
            
        return inet_handle

    def create_connection(  self, 
                            inet_handle, 
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
            inet_inst = obj_manager.ObjectManager.get_obj_by_handle(inet_handle)
        if not inet_inst:
            raise Exception("Invalid Handle")
        if not isinstance(inet_inst, EmuWinInetSession):
            raise Exception("Invalid Object Type")

        if svc_type == IntertetService.INTERNET_SERVICE_FTP:
            try:
                socket.getaddrinfo(host, 21, AF_INET)
            except gaierror:
                return 0xFFFFFFFF
            conn_handle = obj_manager.ObjectManager.create_new_object(EmuWinFtpConnection, inet_inst, host, usr_name, usr_pwd, ctx, port, svc_type, flag)
        elif svc_type == IntertetService.INTERNET_SERVICE_HTTP:
            if port == 80:
                try:
                    socket.getaddrinfo(host, 80, AF_INET)
                except gaierror:
                    return 0xFFFFFFFF
            elif port == 443:
                try:
                    socket.getaddrinfo(host, 443, AF_INET)
                except gaierror:
                    return 0xFFFFFFFF
            else:
                return 0xFFFFFFFF
            conn_handle = obj_manager.ObjectManager.create_new_object(EmuWinHttpConnection, inet_inst, host, ctx, port, svc_type, flag)
        else:
            raise Exception("Not supported in this emulation")

        return conn_handle # return handle of WinHttpSession or WinFtpSession

    def create_http_request(self, 
                            conn_handle,
                            obj_name, 
                            refer=None, 
                            flag=0, 
                            ctx={}, 
                            accept_types=None, 
                            verb='GET', 
                            version=1.1,
                            raw=False)->EmuWinHttpRequest:
        # Respond with
        # HANDLE OpenHttpRequest
        inet_conn = obj_manager.ObjectManager.get_obj_by_handle(conn_handle)
        if not inet_conn:
            raise Exception("Invalid Handle")
        if not isinstance(inet_conn, EmuWinHttpConnection):
            raise Exception("Invalid Object Type")

        http_req_handle = obj_manager.ObjectManager.create_new_object(EmuWinHttpRequest, inet_conn, obj_name, refer, accept_types, verb, version)
        
        return http_req_handle

    def send_http_request(self, http_req_handle, data:bytes=None, redirect=True):
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

        http_req = obj_manager.ObjectManager.get_obj_by_handle(http_req_handle)
        if not http_req:
            raise Exception("Invalid Handle")
        if not isinstance(http_req, EmuWinHttpRequest):
            raise Exception("Invalid Object Type")

        http_req.send_req()

        if redirect and ( 300 <= http_req.resp.status and http_req.resp.status < 400 ):
            redirected_url = resolve_http_redirect(http_req.resp.getheader("Location"))
            p_url = urlparse(redirected_url)
            redi_conn = EmuWinHttpConnection(
                        http_req.conn_instance.instance, 
                        p_url.netloc, 
                        http_req.conn_instance.ctx, 
                        http_req.conn_instance.port, 
                        http_req.conn_instance.svc_type,
                        http_req.conn_instance.http_flag
                    ) 
            redi_req = EmuWinHttpRequest(
                    redi_conn, 
                    p_url.path, 
                    http_req.refer,
                    http_req.accept_types,
                    http_req.verb,
                    http_req.version
                )
            
            redi_req.send_req()
            http_req.change_redirected_resp(redi_req.resp)

        http_req.set_reqinfo()
        return http_req.resp
    
    def recv_http_response(self, http_req_handle, recv_size)->bytes:
        http_req = obj_manager.ObjectManager.get_obj_by_handle(http_req_handle)
        if recv_size == 0:
            buf = http_req.resp.read()
        else:
            buf = http_req.resp.read(recv_size)
        
        recv_sz = len(buf)
        http_req.renew_avaliable_size(recv_sz)
        
        return buf

    def get_resp(self, http_req_handle):
        http_req = obj_manager.ObjectManager.get_obj_by_handle(http_req_handle)
        if not http_req:
            raise Exception("Invalid Handle")
        if not isinstance(http_req, EmuWinHttpRequest):
            raise Exception("Invalid Object Type")

        return http_req.resp

    def close_http_handle(self, http_req_handle):
        http_req = obj_manager.ObjectManager.get_obj_by_handle(http_req_handle)
        if isinstance(http_req, EmuWinHttpRequest):
            http_req.conn_instance.conn.close()
    
        pass
    '''
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
    '''