import re
import struct
from speakeasy_origin.struct import EmuStruct
import speakeasy_origin.windef.nt.ntoskrnl as ntos

def get_bytes(obj):
    """
    Get the bytes represented in the emulation space of the supplied object
    """
    return obj.get_bytes()

def hex_to_double(x):
    x = x.to_bytes(8, 'little')
    x = struct.unpack('d', x)[0]
    return x

def double_to_hex(x):
    return struct.unpack('<Q', struct.pack('<d', x))[0]

def get_char_width(ctx):
    """
    Based on the API name, determine the character width
    being used by the function
    """
    name = ctx.get('func_name', '')
    if name.endswith('A'):
        return 1
    elif name.endswith('W'):
        return 2
    raise Exception('Failed to get character width from function: %s' % (name))

def sizeof(obj):
    if isinstance(obj, EmuStruct):
        return obj.sizeof()
    else:
        raise Exception('Invalid object')

def read_mem_string(emu_eng, address, width=1, max_chars=0)->str:
    """
    Read a string from emulated memory
    """
    char = b'\xFF'
    string = b''
    i = 0

    if width == 1:
        decode = 'utf-8'
    elif width == 2:
        decode = 'utf-16le'
    else:
        raise ValueError('Invalid string encoding')

    while int.from_bytes(char, 'little') != 0:
        if max_chars and i >= max_chars:
            break
        char = emu_eng.mem_read(address, width)

        string += char
        address += width
        i += 1

    try:
        dec = string.decode(decode, 'ignore').replace('\x00', '')
    except Exception:
        dec = string.replace(b'\x00', b'')
    return dec

def mem_string_len(emu_eng, address, width=1):
    """
    Get the length of a string from emulated memory
    """
    slen = -1
    char = b'\xFF'

    while int.from_bytes(char, 'little') != 0:
        char = emu_eng.mem_read(address, width)
        address += width
        slen += 1
    return slen

def mem_copy(emu_eng, dst, src, n):
    """
    Copy bytes from one emulated address to another
    """
    sbytes = emu_eng.mem_read(src, n)
    emu_eng.mem_write(dst, sbytes)
    return n

def mem_write(emu_eng, addr, data:bytes):
    emu_eng.mem_write(addr, data)

    return len(data)

def mem_cast_to_obj(emu_eng, obj, addr):
    struct_bytes = emu_eng.mem_read(addr, sizeof(obj))
    if isinstance(obj, EmuStruct):
        return obj.cast(struct_bytes)
    else:
        raise Exception('Invalid object')

def write_mem_string(emu_eng, string, address, width=1):
    """
    Write string data to an emulated memory address
    """

    if width == 1:
        encode = 'utf-8'
    elif width == 2:
        encode = 'utf-16le'
    else:
        raise ValueError('Invalid string encoding')

    enc_str = string.encode(encode)
    emu_eng.mem_write(address, enc_str)

    return len(enc_str)

def read_ansi_string(emu, addr): # <- warning!
    ans = ntos.STRING(emu.get_ptr_size())

    ans = mem_cast_to_obj(emu.emu_eng, ans, addr)

    string = read_mem_string(emu.emu_eng, ans.Buffer, width=1)
    return string

def read_unicode_string(emu, addr): # <-- warning!
    us = ntos.UNICODE_STRING(emu.get_ptr_size())
    us = mem_cast_to_obj(emu.emu_eng, us, addr)

    string = read_mem_string(emu.emu_eng, us.Buffer, width=2)
    return string

def read_wide_string(emu_eng, addr, max_chars=0):
    string = read_mem_string(emu_eng,addr, width=2, max_chars=max_chars)
    return string

def read_string(emu_eng, addr, max_chars=0):
    string = read_mem_string(emu_eng, addr, width=1, max_chars=max_chars)
    return string


def write_wide_string(emu_eng, string, addr):
    return write_mem_string(emu_eng, string, addr, width=2)

def write_string(emu_eng, string, addr):
    return write_mem_string(emu_eng, string, addr, width=1)

    """
def extract_strings(self):
    
    # Implementation needed
    
    tgt_tag_prefixes = ('emu.stack', 'api')
    ansi_strings = []
    unicode_strings = []
    ret_ansi = []
    ret_unicode = []

    for mmap in self.get_mem_maps():
        tag = mmap.get_tag()
        if tag and tag.startswith(tgt_tag_prefixes) and tag != self.input.get('mem_tag'):
            data = self.mem_read(mmap.get_base(), mmap.get_size()-1)
            ansi_strings += self.get_ansi_strings(data)
            unicode_strings += self.get_unicode_strings(data)

    [ret_ansi.append(a) for a in ansi_strings if a not in ret_ansi]
    [ret_unicode.append(a) for a in unicode_strings if a not in ret_unicode]

    return (ret_ansi, ret_unicode)
    """

def get_unicode_strings(data, min_len=4):
    """Need edit"""
    wstrs = []
    pat = b'(?:[\x20-\x7f]\x00){%d,}' % (min_len)
    res = re.compile(pat)
    hits = res.findall(data)
    offset = 0
    for ws in hits:
        try:
            offset = data.find(ws, offset)
            ws = ws.decode('utf-16le')
            wstrs.append((offset, ws))
            offset += 1
        except UnicodeDecodeError:
            continue
    return wstrs

def make_fmt_str(emu, string, argv):
    """
    Format a string similar to msvcrt.printf
    """

    # Skip over the format string
    args = list(argv)
    new = list(string)
    curr_fmt = ''
    new_fmts = []
    emu_eng = emu.emu_eng

    # Very brittle format string parser, should improve later
    inside_fmt = False
    for i, c in enumerate(string):

        if c == '%':
            if inside_fmt:
                inside_fmt = False
            else:
                inside_fmt = True

        if inside_fmt:
            if c == 'S':
                s = read_wide_string(emu_eng, args.pop(0))
                new_fmts.append(s)
                new[i] = 's'
                inside_fmt = False

            elif c == 's':
                if curr_fmt.startswith('w'):
                    s = read_wide_string(emu_eng, args.pop(0))
                    new[i - 1] = '\xFF'
                    curr_fmt = ''
                    new_fmts.append(s)
                else:
                    s = read_string(emu_eng, args.pop(0))
                    new_fmts.append(s)
            elif c in ('x', 'X', 'd', 'u', 'i'):
                if curr_fmt.startswith('ll'):
                    if emu.get_ptr_size() == 8:
                        new_fmts.append(args.pop(0))
                    else:
                        low = args.pop(0)
                        high = args.pop(0)
                        new_fmts.append(high << 32 | low)
                    new = new[: i - 2] + new[i:]
                    curr_fmt = ''
                else:
                    new_fmts.append(0xFFFFFFFF & args.pop(0))
            elif c == 'c':
                new_fmts.append(0xFF & args.pop(0))
            elif c == 'P':
                new[i] = 'X'
                new_fmts.append(args.pop(0))
            elif c == 'p':
                new[i] = 'x'
                new_fmts.append(args.pop(0))
            elif c == 'l':
                curr_fmt += c
            elif c == 'w':
                curr_fmt += c

        if inside_fmt and c in 'diuoxXfFeEgGaAcspn':
            inside_fmt = False

        if not args:
            break

    new = ''.join(new)
    new = new.replace('\xFF', '')
    new = new % tuple(new_fmts)

    return new

def get_env(emu):
    return emu.env