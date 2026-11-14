import psutil
import win32gui
import win32process

pt_pids = [
    p.pid for p in psutil.process_iter(["name", "pid"]) if "packet" in p.info["name"].lower()
]
print(f"Packet Tracer PIDs: {pt_pids}")

def enum_cb(hwnd, extra):
    _, pid = win32process.GetWindowThreadProcessId(hwnd)
    if pid in pt_pids:
        title = win32gui.GetWindowText(hwnd)
        cls_name = win32gui.GetClassName(hwnd)
        visible = win32gui.IsWindowVisible(hwnd)
        rect = win32gui.GetWindowRect(hwnd)
        print(f"HWND={hwnd} Visible={visible} Rect={rect} Class='{cls_name}' Title='{title}'")

win32gui.EnumWindows(enum_cb, None)
