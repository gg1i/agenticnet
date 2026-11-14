import ctypes
import time

import win32con
import win32gui
import win32service
from PIL import ImageGrab

ctypes.windll.user32.SetProcessDpiAwarenessContext(-4)

hwinsta = win32service.OpenWindowStation('WinSta0', False, win32con.MAXIMUM_ALLOWED)
hwinsta.SetProcessWindowStation()
hdesk = win32service.OpenDesktop('Default', 0, False, win32con.MAXIMUM_ALLOWED)
hdesk.SetThreadDesktop()

hwnd = 2493630
win32gui.ShowWindow(hwnd, win32con.SW_SHOWMAXIMIZED)
win32gui.SetForegroundWindow(hwnd)
time.sleep(0.5)

c_left_rel, c_top_rel, c_right_rel, c_bottom_rel = win32gui.GetClientRect(hwnd)
c_left, c_top = win32gui.ClientToScreen(hwnd, (c_left_rel, c_top_rel))
c_right, c_bottom = win32gui.ClientToScreen(hwnd, (c_right_rel, c_bottom_rel))

print(
    f"Client screen rect: ({c_left}, {c_top}) to ({c_right}, {c_bottom}) -> "
    f"size {c_right - c_left}x{c_bottom - c_top}"
)

img = ImageGrab.grab(bbox=(c_left, c_top, c_right, c_bottom))
img.save("pt_true_physical.png")
print("Saved pt_true_physical.png, size:", img.size)
