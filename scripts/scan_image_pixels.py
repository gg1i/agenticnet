import cv2
import numpy as np

img = cv2.imread('artifacts_pt_live_actual.png')
h, w, c = img.shape
print(f"Image shape: {w}x{h}")

gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
# Find rows and cols that are not 255
non_white_mask = gray < 250
y_indices, x_indices = np.where(non_white_mask)

if len(y_indices) > 0:
    min_x, max_x = np.min(x_indices), np.max(x_indices)
    min_y, max_y = np.min(y_indices), np.max(y_indices)
    print(f"Non-white pixel bounds: X=[{min_x}, {max_x}], Y=[{min_y}, {max_y}]")
    pct = len(y_indices) / (w * h) * 100
    print(f"Total non-white pixels: {len(y_indices)} out of {w * h} ({pct:.2f}%)")
    
    # Save a heatmap or visual map of where pixels are
    vis = np.zeros((h, w), dtype=np.uint8)
    vis[non_white_mask] = 255
    cv2.imwrite('pixel_presence_map.png', vis)
    print("Saved pixel_presence_map.png")
else:
    print("ENTIRE SCREENSHOT IS PURE WHITE!")
