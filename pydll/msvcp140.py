from uc_handler.api_handler import ApiHandler
from uc_handler.api_handler import CALL_CONV as cv
class Msvcp140(ApiHandler):
    api_call = ApiHandler.api_call
    
    def __init__(self, win_emu):
        self.win_emu = win_emu
        self.funcs = {}
        super().__set_api_attrs__(self)