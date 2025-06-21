import asyncio
import pyautogui
import time

from test import find_image_on_screen

class AutoController:
    def __init__(self):
        # Set failsafe and pause between actions
        pyautogui.FAILSAFE = True
        pyautogui.PAUSE = 0.5
    
    def move_to(self, x, y, duration=0.5):
        """Move mouse to specified coordinates"""
        pyautogui.moveTo(x, y, duration=duration)
    
    def click_at(self, x, y, clicks=1):
        """Click at specified coordinates"""
        pyautogui.click(x=x, y=y, clicks=clicks)
    
    def type_text(self, text, interval=0.1):
        """Type text with specified interval between keystrokes"""
        pyautogui.typewrite(text, interval=interval)
    
    async def press_key(self, key):
        """Press a single key"""
        pyautogui.press(key)
    
    def get_mouse_position(self):
        """Get current mouse position"""
        return pyautogui.position()
    
    def screenshot(self, filename):
        """Take a screenshot and save to file"""
        pyautogui.screenshot(filename)
    
    async def wait_until_on_screen(self, image_path, timeout=None, confidence=0.9):
        """
        Find image on screen and return coordinates.
        Keeps waiting until the image is found or timeout is reached.
        
        Args:
            image_path: Path to the image file to locate
            timeout: Maximum time to wait in seconds (None for infinite)
            confidence: Matching confidence threshold (0-1)
        """
        start_time = time.time()
        
        while True:
            try:
                # location = pyautogui.locateOnScreen(image_path, confidence=confidence, grayscale=True)
                location = find_image_on_screen("loading.png", threshold=confidence, show_window=True)
                if location:
                    print(f"Image found at: {location}")
                    return location
            except pyautogui.ImageNotFoundException as e:
                print(f"Image not found yet: {e}")
            
            if timeout is not None and (time.time() - start_time) > timeout:
                return None
            
            await asyncio.sleep(0.5)

    async def hold_keys(self, keys: list[str], duration: float = 1.0) -> None:
        """Hold multiple keys simultaneously for specified duration"""
        for key in keys:
            pyautogui.keyDown(key)

        await asyncio.sleep(duration)
        for key in reversed(keys):
            pyautogui.keyUp(key)

    async def press_keys_down(self, keys: list[str], duration: float = 1.0) -> None:
        """Hold multiple keys simultaneously for specified duration"""
        for key in keys:
            pyautogui.keyDown(key)

    async def press_keys_up(self, keys: list[str]) -> None:
        """Release multiple keys simultaneously"""
        for key in reversed(keys):
            pyautogui.keyUp(key)

    async def move_item_from_player_to_chest(self, item_number: int) -> None:
        row_number = item_number // 5
        column_number = item_number % 5
        # if column_number == 0:
        
        if item_number % 5 == 0:
            column_number = 5
            row_number -= 1
        
        row_to_key_map = {
            0: "z",
            1: "x",
            2: "c",
            3: "v",
            4: "b",
        }
        print(f"Moving item {item_number} from player to chest at row {row_number}, column {column_number} with {str(row_to_key_map[row_number]), str(column_number)}")
        await self.hold_keys([str(row_to_key_map[row_number]), str(column_number)], duration=0.1)
    
    async def move_item_from_chest_to_player(self, item_number: int) -> None:
        row_number = item_number // 5
        column_number = (item_number % 5) + 5

        row_to_key_map = {
            0: "z",
            1: "x",
            2: "c",
            3: "v",
            4: "b",
        }

        await self.hold_keys([row_to_key_map[row_number], column_number], duration=0.5)

controller = AutoController()

# Key up everything
# for i in ['z', 'x', 'c', 'v', 'b']:
#     pyautogui.keyUp(i)
#     for j in range(10):
#         pyautogui.keyUp(str(j))
