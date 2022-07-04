from emuobj import EmuObject
import socket

class EmuSocket(EmuObject):
    SOCKET=0x19190 # unsigned int
    def __init__(self, s, obj):
        super().__init__()
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

class EmuWSKSocket(EmuSocket):
    SOCKET=EmuSocket.SOCKET
    def __init__(self, s, obj, family, stype, protocol, flag):
        super().__init__(s, obj)
        self.family = family
        self.stype = stype
        self.protocol = protocol
        self.flag = flag