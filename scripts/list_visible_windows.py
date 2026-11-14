import win32gui
import win32process

windows = []
def cb(hwnd, _):
    if win32gui.IsWindowVisible(hwnd):
        title = win32gui.GetWindowText(hwnd)
        if title:
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            rect = win32gui.GetWindowRect(hwnd)
            windows.append((pid, title, rect))

win32gui.EnumWindows(cb, None)
for pid, title, rect in windows[:25]:
    print(f"[{pid}] '{title}' at {rect}")
