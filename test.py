import os.path
import emu_handler as e_handler


if __name__ == "__main__":
    target_file = "./sample/peb_teb_test.exe"
    #target_file = "./sample/Downloader.exe"
    emu_handler = e_handler.EmuHandler()
    full_path = os.path.abspath(os.path.join(__file__, os.path.pardir, target_file))
    emu = emu_handler.create_new_emulator(full_path)
    emu.launch()
    print("Emulation Finished")