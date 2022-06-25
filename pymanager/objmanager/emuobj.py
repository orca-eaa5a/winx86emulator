from unicodedata import name


class EmuObject:
    def __init__(self) -> None:
        self.oid = -1
        self.refcount = 0
        self.name = ''
        pass

    def get_oid(self):
        return self.oid

    def set_oid(self, oid):
        self.oid = oid

    def inc_refcount(self):
        self.refcount += 1
    
    def get_refcount(self):
        return self.refcount

    def set_name(self, name):
        self.name = name