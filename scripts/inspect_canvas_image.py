import cv2
import numpy as np

img = cv2.imread('artifacts_pt_live_actual.png')
print('Loaded image shape:', img.shape)

# Convert to grayscale
gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

# The logical workspace canvas is typically in the upper-center area:
# y: from roughly 100 to 750, x: from roughly 50 to 1850
canvas_roi = gray[100:750, 50:1850]
mean_val = np.mean(canvas_roi)
std_val = np.std(canvas_roi)
print(f"Canvas ROI (y:100-750, x:50-1850): mean={mean_val:.2f}, std={std_val:.2f}")

# Threshold to detect non-white pixels (devices and text)
# In Packet Tracer, background is pure white (255)
non_white = np.sum(canvas_roi < 250)
total_pixels = canvas_roi.size
pct = non_white / total_pixels * 100
print(f"Non-white pixels on canvas: {non_white} / {total_pixels} ({pct:.2f}%)")

# Let's find contours of objects on canvas
_, thresh = cv2.threshold(canvas_roi, 250, 255, cv2.THRESH_BINARY_INV)
contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
print(f"Total contours found on canvas: {len(contours)}")

# Filter contours by area to find device icons
device_boxes = []
for c in contours:
    x, y, w, h = cv2.boundingRect(c)
    area = cv2.contourArea(c)
    if w > 20 and h > 20:
        device_boxes.append((x + 50, y + 100, w, h, area))

print(f"Detected potential device boxes (>20x20): {len(device_boxes)}")
for idx, (x, y, w, h, a) in enumerate(device_boxes):
    print(f"  Box {idx+1}: at x={x}, y={y}, size={w}x{h}, area={a}")
