import cv2

img = cv2.imread('artifacts_pt_live_actual.png')
h, w, c = img.shape
print(f"Image shape: {w}x{h}")

# Check top region (menu + toolbars): y from 0 to 120
top = img[0:120, 0:w]
cv2.imwrite('crop_top.png', top)
print("Saved crop_top.png")

# Check bottom region (device palette): y from h-250 to h
bottom = img[h-250:h, 0:w]
cv2.imwrite('crop_bottom.png', bottom)
print("Saved crop_bottom.png")

# Check left region: x from 0 to 120
left = img[0:h, 0:120]
cv2.imwrite('crop_left.png', left)
print("Saved crop_left.png")

# Check right region: x from w-120 to w
right = img[0:h, w-120:w]
cv2.imwrite('crop_right.png', right)
print("Saved crop_right.png")
