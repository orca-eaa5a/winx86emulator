import speakeasy.winenv.defs.windows.windows as windefs
from cb_handler import ApiHandler
from cb_handler import CALL_CONV as cv
from speakeasy_origin.windef.winsock.ws2_32 import WSAData
class Ws2_32(ApiHandler):
    api_call = ApiHandler.api_call
    
    def __init__(self, proc):
        self.funcs = {}
        super().__set_api_attrs__(self)

    @api_call('WSAStartup', argc=2)
    def WSAStartup(self, proc, argv, ctx={}):
        '''
        int WSAStartup(
            WORD      wVersionRequired,
            LPWSADATA lpWSAData
        );
        '''
        ver_req, pWSAData = argv
        high, low = ver_req >> 8 , ver_req & 0xFF
        wsa_data = WSAData(proc.ptr_size)
        wsa_data.wVersion = ver_req
        wsa_data.wHighVersion = (2 << 8) + 2

        proc.uc_eng.mem_wirte(pWSAData, wsa_data.get_bytes())

        return 0

    
