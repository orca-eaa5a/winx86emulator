FILE_ATTRIBUTE_NORMAL=0x80

class DesiredAccess:
    FILE_READ_DATA=0x1
    FILE_WRITE_DATA=-0x2
    FILE_APPEND_DATA=0x4
    FILE_READ_EA=0x8
    FILE_READ_ATTRIBUTES=0x80
    FILE_WRITE_ATTRIBUTES=0x100
    DELETE=0x10000
    GENERIC_READ=0x80000000
    GENERIC_WRITE=0x40000000
    GENERIC_EXECUTE=0x20000000
    GENERIC_ALL=0x10000000

class CreationDisposition:
    CREATE_NEW=0x1 # Creates a new file, only if it does not already exist.
    CREATE_ALWAYS=0x2 # Create a new file always.
    OPEN_EXISTING=0x3 
    OPEN_ALWAYS=0x4 # Opens a file, always. If the specified file does not exist and is a valid path to a writable location, the function creates a file
    TRUNCATE_EXISTING=0x5