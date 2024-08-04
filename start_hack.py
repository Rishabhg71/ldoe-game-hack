import frida
import signal
import sys
import asyncio
import win32gui
import win32con
import time

def handle_interrupt(signal, frame):
    print("Script terminated by user")
    sys.exit(0)

# Register the signal handler for Ctrl + C
signal.signal(signal.SIGINT, handle_interrupt)


process = frida.get_usb_device().attach('zombie.survival.craft.z', realm="emulated")

class Controller:
    def __init__(self) -> None:
        # self.hwnd = win32gui.FindWindow(None, "dnplayer.exe dnplayer.exe (32 bit) - Search - Brave")  # Replace with your application's window title
        self.hwnd = win32gui.FindWindow(None, "*bluestacks.conf - Notepad")  # Replace with your application's window title
        # self.hwnd = win32gui.(None, "Untitled - Notepad")  # Replace with your application's window title
        if self.hwnd == 0:
            raise Exception("Dint find that window")

    def send_key(self, key):
        win32gui.PostMessage(self.hwnd, win32con.WM_KEYDOWN, key, 0)
        time.sleep(0.05)
        win32gui.PostMessage(self.hwnd, win32con.WM_KEYUP, key, 0)


    def click_on(self, button: str, time: float):
        pass

class Server:
    script: frida.core.Script
    def __init__(self) -> None:
        pass
    
    def on_message(self, message, data):
        print("Message", message)
        self.script.post("message")
    
    
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
            res = await script.exports_async.click()
            # print(res)

        if command == "start":
            res = await script.exports_async.start()
            print(res)

try:
    asyncio.run(main())
finally:
    pass
