import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[+] {message['payload']}")
    elif message['type'] == 'error':
        print(f"[-] {message['stack']}")

# Connect to the device
device = frida.get_usb_device()

# Spawn the application
pid = device.spawn(["zombie.survival.craft.z"])
session = device.attach(pid)

# Load the script
with open("dist/agent.js", "r") as f:
    script = session.create_script(f.read())

# Set up the message handler
script.on("message", on_message)

# Load the script
script.load()

# Resume the application
device.resume(pid)

# Keep the script running
sys.stdin.read()