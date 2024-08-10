import frida
# import sys

# process = frida.get_usb_device().attach('zombie.survival.craft.z', realm="emulated")
# script = process.create_script("""
#     recv('poke', function onMessage(pokeMessage) { 
#                                console.log("helo")
#                                send('pokeBack');
#      });
# """)
# def on_message(message, data):
#     print(message)
# script.on('message', on_message)
# script.load()
# script.post({"type": "poke"})
# sys.stdin.read()


process = frida.get_local_device()
print(process)
process = frida.get_usb_device()
print(process)
process = frida.get_remote_device()
print(process)