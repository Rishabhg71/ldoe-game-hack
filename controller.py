import asyncio
import threading
import time
from typing import Literal
from ppadb.client import Client as AdbClient

BUTTON_LOCATIONS = {
    "AUTO": (50, 840),
    "PUT_ALL": (1300, 820),
    "TAKE_ALL": (930, 820),
    "USE_IN_INVENTORY": (170, 820),
    "SPLIT_IN_INVENTORY": (400, 820),
    "DELETE_INVENTORY": (675, 820),
    "SNEAK": (1550, 840),
    "USE": (1350, 800),
    "ATTACK": (1480, 670),
    "BACKPACK": (1240, 835),
    "CRAFT_BUTTON": (1150, 825),
    "CLOSE_PANEL": (1540, 150),
    "CRAFT_HATCHET_LOCATION": (180, 230),
    "CRAFT_PICKAXE_LOCATION": (340, 230),
    "FIANL_PRODUCTS": (1220, 480),
    "DPAD_CENTER": (200, 700),
    "DPAD_W": (200, 600),
    "DPAD_A": (100, 700),
    "DPAD_D": (300, 700),
    "DPAD_S": (200, 800),
    "DPAD_WA": (130, 630),
    "DPAD_WD": (270, 630),
    "DPAD_SA": (130, 765),
    "DPAD_SD": (270, 765),
}





class Controller:
    def __init__(self) -> None:
        self.client = AdbClient()
        self.device = self.client.devices()[0]  # Get the first connected device

    def tap(self, x, y, hold_for=None):
        if hold_for:
            self.hold_tap(x, y, hold_for)
        else:
            self.device.shell(f"input tap {x} {y}")

    def hold_tap(self, x, y, duration):
        self.device.shell(
            f"input touchscreen swipe {x} {y} {x} {y} {int(duration * 1000)}"
        )

    def swipe(self, x1, y1, x2, y2, duration):
        self.device.shell(
            f"input touchscreen swipe {x1} {y1} {x2} {y2} {int(duration * 1000)}"
        )

    async def swipe_hold(self, x1, y1, x2, y2, duration):
        self.device.shell(
            f"input touchscreen swipe {x1} {y1} {x2} {y2} {int(0.3 * 1000)}"
        )
        
        self.device.shell(
            f"input touchscreen swipe {x2} {y2} {x2} {y2} {int(duration * 1000)}"
        )
    
    def press_auto(self):
        x, y = BUTTON_LOCATIONS["AUTO"]
        self.tap(x, y)

    def press_sneak(self):
        x, y = BUTTON_LOCATIONS["SNEAK"]
        self.tap(x, y)

    def press_use(self, hold_for=None):
        x, y = BUTTON_LOCATIONS["USE"]
        self.tap(x, y, hold_for)

    def press_attack(self, hold_for=None):
        x, y = BUTTON_LOCATIONS["ATTACK"]
        if hold_for:
            self.hold_tap(x, y, hold_for)
        else:
            self.tap(x, y)

    def press_backpack(self):
        x, y = BUTTON_LOCATIONS["BACKPACK"]
        self.tap(x, y)

    def press_craft_button(self):
        x, y = BUTTON_LOCATIONS["CRAFT_BUTTON"]
        self.tap(x, y)
    
    def press_take_all(self):
        x, y = BUTTON_LOCATIONS["TAKE_ALL"]
        self.tap(x, y)

    def press_put_all(self):
        x, y = BUTTON_LOCATIONS["PUT_ALL"]
        self.tap(x, y)

    def press_close_panel(self):
        x, y = BUTTON_LOCATIONS["CLOSE_PANEL"]
        self.tap(x, y)

    def craft_hatchet(self):
        x, y = BUTTON_LOCATIONS["CRAFT_HATCHET_LOCATION"]
        self.tap(x, y)

    def craft_pickaxe(self):
        x, y = BUTTON_LOCATIONS["CRAFT_PICKAXE_LOCATION"]
        self.tap(x, y)

    def run_in_thread(self, func, *args, **kwargs):
        thread = threading.Thread(target=func, args=args, kwargs=kwargs)
        return thread

    def double_click_for_inventory(self, row:int, col:int):
        CELL1_CENTER = (150, 165)
        CELL_HALF_LENGTH = (210 - 90)
        X = CELL1_CENTER[0] + (CELL_HALF_LENGTH * row)
        Y = CELL1_CENTER[1] + (CELL_HALF_LENGTH * col)
        print(X, Y, "DSDSD", row, col)
        def tap(x, y):
            self.device.shell(f"input tap {x} {y}")
        
        tap(X, Y)
        time.sleep(0.5)
        thread1 = self.run_in_thread(tap, X, Y)
        thread2 = self.run_in_thread(tap, X, Y)

        thread1.start()
        thread2.start()
        thread1.join()
        thread2.join()

    def double_click_final_products(self):
        X, Y = BUTTON_LOCATIONS["FIANL_PRODUCTS"]
        def tap(x, y):
            self.device.shell(f"input tap {x} {y}")

        tap(X, Y)
        time.sleep(0.5)


        thread1 = self.run_in_thread(tap, X, Y)
        thread2 = self.run_in_thread(tap, X, Y)
        thread1.start()
        thread2.start()
        thread1.join()
        thread2.join()
        # time.sleep()


    def run(self, direction: Literal["W", "A", "S", "D", "WA", "WD", "SA", "SD"]):
        centerX, centerY = BUTTON_LOCATIONS["DPAD_CENTER"]
        destination = (centerX, centerY)
        if direction == "W":
            destination = BUTTON_LOCATIONS["DPAD_W"]
        elif direction == "A":
            destination = BUTTON_LOCATIONS["DPAD_A"]
        elif direction == "S":
            destination = BUTTON_LOCATIONS["DPAD_S"]
        elif direction == "D":
            destination = BUTTON_LOCATIONS["DPAD_D"]
        elif direction == "WA":
            destination = BUTTON_LOCATIONS["DPAD_WA"]
        elif direction == "WD":
            destination = BUTTON_LOCATIONS["DPAD_WD"]
        elif direction == "SA":
            destination = BUTTON_LOCATIONS["DPAD_SA"]
        elif direction == "SD":
            destination = BUTTON_LOCATIONS["DPAD_SD"]

        self.swipe(centerX, centerY, destination[0], destination[1], duration=0.3)

if __name__ == "__main__":
    asyncio.run(Controller().double_click_for_inventory(0, 0))
    
# Controller().press_attack(hold_for=5)
# Controller().press_put_all()