import json
from typing import Literal
import frida
import signal
import sys
import asyncio
import win32gui
import win32con
import time

from controller import Controller

def handle_interrupt(signal, frame):
    print("Script terminated by user")
    sys.exit(0)

# Register the signal handler for Ctrl + C
signal.signal(signal.SIGINT, handle_interrupt)


device = frida.get_usb_device()

# process = device.attach('zombie.survival.craft.z', realm="emulated")
process = device.attach('Last Day On Earth: Survival', realm="emulated")

class Server:
    script: frida.core.Script
    control: Controller
    def __init__(self) -> None:
        self.control = Controller()
    
    def craft_item(self, name: Literal['hatchet', "pickaxe"]):
        if name == "pickaxe":
            self.control.craft_pickaxe()
            self.control.press_craft_button()
            return
        if name == "hatchet":
            self.control.craft_hatchet()
            time.sleep(1)
            self.control.press_craft_button()
            return
        
        raise Exception("No item was picked")


    def on_message(self, message, data):
        if message['type'] == "error":
            print(message)
            return
        payload = message["payload"]
        event = payload['event']
        print(f"[SERVER] executing event {event}")
        if event == "close_inventory":
            self.control.press_close_panel()
        if event == "use":
            self.control.press_use()
        if event == "put_all":
            self.control.press_put_all()
        if event == "take_all":
            self.control.press_take_all()
        if event == "auto":
            self.control.press_auto()
        
        if event == "craft_button":
            self.control.press_craft_button()
        if event == "craft_item":
            item_name = payload["args"][0]
            print(item_name)
            self.craft_item(item_name)
        
        if event == "dbl_click_inventory":
            row = int(payload["args"][0]) - 1
            col = int(payload["args"][1]) - 1
            self.control.double_click_for_inventory(row, col)

        if event == "double_click_final_products":
            self.control.double_click_final_products()
        
        if event == "run":
            direction = payload["args"][0]
            times = payload["args"][1]
            for i in range(int(times)):
                self.control.run(direction)

        print(f"[SERVER] Responding back to client to event: {event}", message)
        self.script.post({"type": event})
    
    # def on_message(self, message, data):
    #     # payload = message["payload"]
    #     print(message)
    #     print(f"[SERVER] Responding back to client")
    #     self.script.post({"type": "poke"})
            
    
    def create_script(self):
        with open('./dist/agent.js', 'r', encoding='utf-8') as file:
            script = file.read()
        self.script = process.create_script(script)
        self.script.on('message', self.on_message)
        return self.script

async def main():
    server = Server()
    # controller.send_key(ord('c'))
    while True:
        command = input("Enter command:")
        script = server.create_script()
        script.load()
        if command == "click":
            # res = script.exports_sync.click()
            res = script.exports_sync.click()
            # print(res)

        if command == "start":
            res = await script.exports_async.start()
            print(res)

        if command == "test":
            res = await script.exports_async.test()
            print(res)

        if command == "hook":
            res = script.exports_sync.hook()
            print(res)

try:
    asyncio.run(main())
finally:
    pass
