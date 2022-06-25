import emu_handler as e_handler


if __name__ == "__main__":
    target_file = "./sample/File_IO.exe"
    #target_file = "./sample/Downloader.exe"
    emu_handler = e_handler.EmuHandler()
    emu = emu_handler.create_new_emulator(target_file)
    emu.launch()
    print("Emulation Finished")