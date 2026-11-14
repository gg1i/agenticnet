import cv2

bottom = cv2.imread('crop_bottom.png')
bh, bw, _ = bottom.shape
# Remember crop_bottom starts at y = 991 - 250 = 741 in the original 1920x991 image!
y_offset = 741

gray = cv2.cvtColor(bottom, cv2.COLOR_BGR2GRAY)

# Find areas that are not uniform background
edges = cv2.Canny(gray, 50, 150)
contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

items = []
for c in contours:
    x, y, w, h = cv2.boundingRect(c)
    if 15 < w < 120 and 15 < h < 120:
        orig_y = y + y_offset
        items.append((x, orig_y, w, h, x / 1920.0, orig_y / 991.0))

print(f"Detected {len(items)} UI elements in bottom palette:")
# Sort by x coordinate
items.sort(key=lambda it: (it[1], it[0]))
for idx, (x, y, w, h, rx, ry) in enumerate(items[:30]):
    print(f"  Item {idx+1}: rect=({x}, {y}, {w}, {h}) -> rx={rx:.3f}, ry={ry:.3f}")
