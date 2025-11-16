import webview as wv
import ctypes
import ctypes.wintypes as wintypes
from tkinter import filedialog

PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

# Define argument and return types for CreateRemoteThread
kernel32.CreateRemoteThread.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    ctypes.c_size_t,
    wintypes.LPVOID,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD)
]
kernel32.CreateRemoteThread.restype = wintypes.HANDLE

class API:
    def inject_dll(self, pid, dll_path):
        dll_path_bytes = dll_path.encode('ascii')

        # 1. Open target process
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not h_process:
            return f"❌ Error: Failed to open process PID {pid}"

        # 2. Allocate memory in target process
        arg_address = kernel32.VirtualAllocEx(h_process, None, len(dll_path_bytes), MEM_COMMIT, PAGE_READWRITE)
        if not arg_address:
            return "❌ Error: Failed to allocate memory in process"

        # 3. Write DLL path to allocated memory
        written = ctypes.c_size_t(0)
        kernel32.WriteProcessMemory(h_process, arg_address, dll_path_bytes, len(dll_path_bytes), ctypes.byref(written))

        # 4. Get address of LoadLibraryA
        kernel32.GetModuleHandleA.argtypes = [wintypes.LPCSTR]
        kernel32.GetModuleHandleA.restype = wintypes.HMODULE

        kernel32.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
        kernel32.GetProcAddress.restype = wintypes.LPVOID

        h_kernel32 = kernel32.GetModuleHandleA(b"kernel32.dll")
        load_library_addr = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryA")

        # 5. Create remote thread
        thread_id = ctypes.c_ulong(0)
        result = kernel32.CreateRemoteThread(h_process, None, 0, load_library_addr, arg_address, 0, ctypes.byref(thread_id))
        if not result:
            return "❌ Error: Failed to create remote thread"

        return f"✅ DLL successfully injected into PID {pid}"

    def path_dll(self):
        return filedialog.askopenfilename(filetypes=[("DLL files", "*.dll")])

if __name__ == '__main__':
    api = API()
    wv.create_window('🧬 DLL Injector', 'index.html', js_api=api, resizable=False)
    wv.start()