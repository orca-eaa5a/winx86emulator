import speakeasy.windows.windows.windows as win_const
from unicorn.unicorn_const import UC_ARCH_X86, UC_ERR_EXCEPTION
from cb_handler import CALL_CONV as cv
from cb_handler import ApiHandler
import common

class Shlwapi(ApiHandler):
    api_call = ApiHandler.api_call

    def __init__(self, win_emu):
        self.win_emu = win_emu
        self.funcs = {}
        super().__set_api_attrs__(self) # initalize info about each apis
        pass

    @api_call('StrStr', argc=2, conv=cv.CALL_CONV_STDCALL)
    def StrStr(self, proc, argv, ctx={}):
        '''
        PCSTR StrStrA(
            PCSTR pszFirst,
            PCSTR pszSrch
        );
        '''
        pTargStr, pSrchStr = argv
        cw = common.get_char_width(ctx)
        targ_str = proc.read_string(pTargStr, cw)
        srch_str = proc.read_string(pSrchStr, cw)
        idx = targ_str.find(srch_str)
        
        if idx == -1:
            return 0
        return idx
        
            