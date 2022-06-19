import fs_emu_util
if __name__ == '__main__':
    path = "c:/1/2/.././3/wow.txt"
    p = fs_emu_util.convert_winpath_to_emupath(path)
    print(p["vl"], p["ps"])