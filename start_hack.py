import json
from typing import Literal
import frida
import signal
import sys
import asyncio
from controller import controller

def handle_interrupt(signal, frame):
    print("Script terminated by user")
    sys.exit(0)

# Register the signal handler for Ctrl + C
signal.signal(signal.SIGINT, handle_interrupt)


device = frida.get_usb_device()


process = device.attach('zombie.survival.craft.z', realm="emulated")
# process = device.attach('Last Day On Earth: Survival', realm="emulated")

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

async def put_items_in_chest(script: frida.core.Script):
    res = await script.exports_async.getbackpack()
    
    chest_sort_order = [
        ["stone"],
        ["wood", "resource_plank_1"],
        ["carrot", "berry", "full_bottle"],
        ["resource_fiber", "resource_seed", "resource_rope"],
        ["wire", "screws", "duct_tape", "rubber_parts"],
    ]

    
    for chest_type in chest_sort_order:
        print(f"Current backpack contents: {json.dumps(res, indent=2)}")
        await script.exports_async.movetile(1, "down")
        await asyncio.sleep(3)
        await controller.hold_keys('e', duration=0.5)
        await asyncio.sleep(1)

        for item in res:
            # Open the chest


            # Check if the item is in the current chest type
            item_number = item['cellIndex']
            if item['name'] not in chest_type:
                continue

            print(f"Moving item {item['name']} from player to chest... {item['cellIndex']}")
            await controller.move_item_from_player_to_chest(item_number)
            await asyncio.sleep(3)


        # Close the chest
        # await asyncio.sleep(3)
        # await script.exports_async.getchestitems()
        # print(f"Current chest items: {json.dumps(res, indent=2)}")
        # await asyncio.sleep(1)
        await controller.hold_keys('f', duration=0.5)
        await asyncio.sleep(3)

def find_item_in_player_items(player_items, item_name):
    x = 0
    for item in player_items:
        if item['name'] == item_name:
            return item, x
        x += 1
    return None, -1


async def put_items_in_workshops(script: frida.core.Script):
    res = await script.exports_async.getbackpack()
    
    workbench_order = {
        "wood_workbench1": ["wood"],
        "wood_workbench2": ["wood"],
        "campfire1": ["resource_plank_1", "resource_plank_1"],
        "campfire2": ["resource_plank_1", "resource_plank_1"],
        "furnace1": ["resource_charcoal", "resource_ore_1"],
        "furnace2": ["resource_charcoal", "resource_ore_1"],
        "tanning_rack1": ["resource_fiber"],
        "tanning_rack2": ["resource_fiber"],
    }

    await script.exports_async.movetile(0.25, "left")
    for workbench, to_place_items in workbench_order.items():
        player_items: list[dict] = await script.exports_async.getbackpack()
        # print(f"Current backpack contents: {json.dumps(res, indent=2)}")
        await script.exports_async.movetile(1, "up")
        await asyncio.sleep(3)
        await controller.hold_keys('e', duration=0.5)
        await asyncio.sleep(1)
        
        # Pickup created items from the workbench
        await controller.hold_keys(["c", "9"], duration=0.5)

        for to_place_item in to_place_items:
            inventory_item, index = find_item_in_player_items(player_items, to_place_item)
            print(f"Looking for item {to_place_item} in player items... Found: {inventory_item}")
            if inventory_item:
                popped_item = player_items.pop(index)
                await controller.move_item_from_player_to_chest(popped_item['cellIndex'])
                await asyncio.sleep(1)

        await asyncio.sleep(1)
        await controller.press_key('f')
        await asyncio.sleep(1)

    
    # For farmland
    await script.exports_async.movetile(1, "up")
    for _ in range(2):
        await controller.hold_keys('e', duration=0.5)
        await asyncio.sleep(1)
        player_items: list[dict] = await script.exports_async.getbackpack()
        await controller.hold_keys(["c", "9"], duration=0.5)
        for item in player_items:
            if item['name'] == "resource_seed":
                print(f"Moving item {item['name']} from player to farmland... {item['cellIndex']}")
                await controller.move_item_from_player_to_chest(item['cellIndex'])
                await asyncio.sleep(3)
                break

        await controller.press_key('f')
        await asyncio.sleep(3)        
        if _ == 0:
            await script.exports_async.movetile(1.5, "right")
    



async def start_bot(server: Server, script: frida.core.Script):
    # print("Starting bot... Make sure to be at home base")
    # await asyncio.sleep(5)
    
    # print("Moving forward and right...")
    # await controller.hold_keys(['w', 'd'], duration=8.0)
    
    # print("Waiting for 20 seconds...")
    # await asyncio.sleep(20)
    
    # print("Executing move command...")
    # await script.exports_async.move()
    
    # print("Waiting for 15 minutes...")
    # await asyncio.sleep(13 * 60)  # Sleep for 15 minutes

    # print("Entering location...")
    # await script.exports_async.enterlocation()
    # await asyncio.sleep(15)

    # print("Opening inventory...")
    # await controller.press_key('p')
    # await asyncio.sleep(1)

    # running = True

    # async def check_until_full():
    #     nonlocal running
    #     print("Starting backpack check loop...")
    #     while running:
    #         backpack = await script.exports_async.getbackpack()
    #         print(f"Current backpack contents: {backpack}")
    #         if len(backpack) == 15:
    #             print("Backpack is full - time to go back home")
    #             running = False
    #         await asyncio.sleep(5)

    # async def wait_for_health():
    #     nonlocal running
    #     print("Starting health monitoring loop...")
    #     while running:
    #         health = await script.exports_async.gethealth()
    #         print(f"Current health: {health}")
    #         if health < 70:
    #             print("Health is low, using healing item...")
    #             await controller.press_key('1')
                
    #         await asyncio.sleep(2)
    
    # print("Starting monitoring tasks...")
    # await asyncio.gather(check_until_full(), wait_for_health())

    # print("Returning home...")
    # await controller.press_keys_up(['w'])
    
    # await asyncio.sleep(5)
    # await controller.press_keys_down(['w'])
    # box = await controller.wait_until_on_screen('loading.png', timeout=30)
    # if box:
    #     print("Loading screen detected, exiting...", box)
    # else:
    #     print("Loading screen not detected, continuing...")
    
    # await controller.press_keys_up(['w'])

    # await asyncio.sleep(10)
    # print("Going back to home base...")
    # await script.exports_async.move("home")
    # await asyncio.sleep(13 * 60)  # Sleep for 15 minutes
    
    # await script.exports_async.enterlocation()
    # print("On loading screen, waiting for 15 seconds...")
    # await asyncio.sleep(10)
    # await script.exports_async.movetile(2)
    # await asyncio.sleep(1)
    # print("Pressing 'e' to interact... to open chest")
    # await controller.press_key('e')
    # await asyncio.sleep(1)
    # print("Pressing 'e' to interact... to put all items in chest")
    # await controller.press_key('e')
    await put_items_in_workshops(script)
    print("Putting items in chests... All done with workshops")
    await put_items_in_chest(script)





async def main():
    server = Server()
    # controller.send_key(ord('c'))
    while True:
        command = input("Enter command:")
        script = server.create_script()
        script.enable_debugger()
        script.load()
        if command == "main":
            res = await script.exports_async.main()
            print(res)

        if command == "test":
            res = await script.exports_async.test()
            print(res)

        if command == "move":
            res = await script.exports_async.move("Trees_01_1")
            print(res)
        
        if command == "movetile":
            res = await script.exports_async.movetile(2)
            print(res)

        if command == "gethealth":
            res = await script.exports_async.gethealth()
            print(res)

        if command == "trace":
            res = await script.exports_async.trace()
            print(res)

        if command == "loop":
            while True:
                res = await script.exports_async.getbackpack()
                print(res)
                health = await script.exports_async.gethealth()
                print(health)
                await asyncio.sleep(5)

        if command == "back":
            res = await script.exports_async.getbackpack()
            print(res)
            if len(res) == 15:
                print("time to go back home")
            # res = await script.exports_async.getbackpack()
            # print(res)

        if command == "start":
            await start_bot(server, script)

        if command == "getchestitems":
            res = await script.exports_async.getchestitems()
            print(res)

        if command == "moveitemsfromplayertochest":
            res = await script.exports_async.moveitemsfromplayertochest()
            print(res)

try:
    asyncio.run(main())
finally:
    pass
