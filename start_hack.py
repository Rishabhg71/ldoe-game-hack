import json
from typing import Literal
import frida
import signal
import sys
import asyncio

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


    def on_message(self, message, data):
        return
    
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
        if command == "main":
            res = script.exports_sync.main()
            print(res)



try:
    asyncio.run(main())
finally:
    pass
