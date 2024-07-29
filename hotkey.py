import frida
import signal
import sys
import asyncio

def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])

def handle_interrupt(signal, frame):
    print("Script terminated by user")
    sys.exit(0)

# Register the signal handler for Ctrl + C
signal.signal(signal.SIGINT, handle_interrupt)

with open('./dist/agent.js', 'r', encoding='utf-8') as file:
    script = file.read()

process = frida.get_usb_device().attach('zombie.survival.craft.z', realm="emulated")
script = process.create_script(script)
script.on('message', on_message)
script.load()

async def main():
    
    while True:
        command = input("Enter command:")
        if command == "start":
            res = await script.exports_async.startApp()
            print(res)

try:
    asyncio.run(main())
finally:
    pass
