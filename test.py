import pyautogui
import cv2
import numpy as np

def find_image_on_screen(template_path='loading.png', threshold=0.8, show_window=False):
    template = cv2.imread(template_path, cv2.IMREAD_COLOR)
    if template is None:
        raise FileNotFoundError(f"{template_path} not found in the current directory.")

    w, h = template.shape[1], template.shape[0]

    if show_window:
        cv2.namedWindow("Image Search", cv2.WINDOW_NORMAL)

    # Take a screenshot using pyautogui
    screenshot = pyautogui.screenshot()
    screenshot = cv2.cvtColor(np.array(screenshot), cv2.COLOR_RGB2BGR)

    # Perform template matching
    res = cv2.matchTemplate(screenshot, template, cv2.TM_CCOEFF_NORMED)
    loc = np.where(res >= threshold)

    found = False
    result_img = screenshot.copy()
    for pt in zip(*loc[::-1]):
        found = True
        if show_window:
            cv2.rectangle(result_img, pt, (pt[0] + w, pt[1] + h), (0, 255, 0), 2)

    if show_window:
        cv2.imshow("Image Search", result_img)
        cv2.waitKey(500)  # Show window for 500ms
        cv2.destroyAllWindows()

    return found

# Example usage:
# result = find_image_on_screen('loading.png', show_window=True)
# print(result)
