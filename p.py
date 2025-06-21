import pyautogui
import time

try:
    print("Press Ctrl+C to stop tracking mouse position.")
    while True:
        # Get current mouse position
        x, y = pyautogui.position()
        
        # Print the position
        print(f"Mouse position: x={x}, y={y}")
        
        # Wait for 1 second
        time.sleep(1)
except KeyboardInterrupt:
    print("\nProgram stopped.")