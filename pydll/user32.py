import speakeasy.winenv.defs.windows.windows as windefs
from cb_handler import ApiHandler
from cb_handler import CALL_CONV as cv

class User32(ApiHandler):
    name = "user32"
    api_call = ApiHandler.api_call
    
    def __init__(self):

        self.funcs = {}
        self.data = {}
        self.window_hooks = {}
        self.handle = 0
        self.win = None
        self.handles = []
        self.timer_count = 0
        

        super().__set_api_attrs__(self)