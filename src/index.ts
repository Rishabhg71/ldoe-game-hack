import "frida-il2cpp-bridge";
import * as fs from "fs";
import * as path from "path";
console.log("[CLIENT]Frida Loaded Successfully");

const TIMEOUT = 30000; // 30 seconds

type DpadDirection = "W" | "A" | "S" | "D" | "WA" | "WD" | "SA" | "SD";
type ControlEvents = "attack" | "auto" | "use" | "take_all" | "put_all" | "close_inventory" | "run" | "craft_button" | "craft_item" | "dbl_click_inventory" | "double_click_final_products" | "double_click_final_products";
type LocationNames = "home" | "Trees_01_1";
type BackpackItems = {
    [key: string]: { amount: number, object: Il2Cpp.Object[] },
};
type BackpackItemsWithIndex = {
    [key: number]: { amount: number, object: Il2Cpp.Object, itemName: string },
};


const cellIndexToCords = (index: number) => {
    const x = index % 5;
    const y = Math.floor(index / 5) + 1;
    return [x, y];
}

const wait = (time: number) => new Promise((resolve) => setTimeout(resolve, time));
class ObjectGetters {

    public static getDpad() {
        const ui = ObjectGetters.waitForUi();
        const dpad = ui.field<Il2Cpp.Object>("DpadController")?.value;
        if (!dpad) throw Error("dpad is null");
        return dpad;
    }

    public static getLocationDescriptionFor(place: LocationNames) {
        const Client = Il2Cpp.domain.assembly("Client").image;
        const GlobalMapPointController = Client.class("Assets.Core.Game.GlobalMap.GlobalMapPointController");
        const arr1 = Il2Cpp.gc.choose(GlobalMapPointController);
        console.log("[CLIENT]Number Assets.Core.Game.GlobalMap.GlobalMapPointController ->", arr1.length);

        for (let index = 0; index < arr1.length; index++) {
            const element = arr1[index];
            const name = element.field<Il2Cpp.Object>("_locationViewDescription").value.method("get_Id").invoke();
            // if (String(name).replaceAll('"', "") === "Trees_01_1") {
            if (String(name).replaceAll('"', "") === place) {
                return element.field<Il2Cpp.Object>("_locationDescription").value;
            }
        }
        throw Error("Location you tried to select is not found");
    }

    public static getInventoryHandler() {
        // Will get the first instance of the InventoryHandler and then we can access the ChestInventory
        const Client = Il2Cpp.domain.assembly("Client").image;
        const GlobalMapPointController = Client.class("Assets.Core.Game.Dialogs.Inventory.InventoryHandler");
        const arr1 = Il2Cpp.gc.choose(GlobalMapPointController);
        console.log("[CLIENT]Number Assets.Core.Game.Dialogs.Inventory.InventoryHandler ->", arr1.length);

        for (let index = 0; index < arr1.length; index++) {
            const element = arr1[index];
            return element;
        }
        throw Error("Location you tried to select is not found");
    }


    public static getMap() {
        const Client = Il2Cpp.domain.assembly("Client").image;

        const GlobalMapMovement = Client.class("Assets.Core.Models.GlobalMapMovementModel.GlobalMapMovement");
        const arr = Il2Cpp.gc.choose(GlobalMapMovement);
        console.log("[CLIENT]Number of instances of Assets.Core.Models.GlobalMapMovementModel.GlobalMapMovement ->", arr.length);
        for (let index = 0; index < arr.length; index++) {
            const element = arr[index];
            return element;
        }
        throw Error("GlobalMapMovement not found");
    }

    public static waitForPlayer(): 
        Il2Cpp.Object
    {
        const Client = Il2Cpp.domain.assembly("Client").image;

        const PlayerClass = Client.class("Assets.Core.Models.Users.Player");

        const arr = Il2Cpp.gc.choose(PlayerClass)
        console.log("[CLIENT]Number of instances of Assets.Core.Models.PlayerClass ->", arr.length);

        for (let index = 0; index < arr.length; index++) {
            const element = arr[index];
            return element;
        }
        throw Error("PlayerObject not found");

    }

    public static listToEnumerable(list: Il2Cpp.Object) {
        return list.method<Il2Cpp.Object>("GetEnumerator").invoke();
    }
    public static *listToGenerator(list: Il2Cpp.Object) {
        const enumerator = list.method<Il2Cpp.Object>("GetEnumerator").invoke();
        while (enumerator.method<boolean>("MoveNext").invoke()) {
            yield enumerator.method<Il2Cpp.Object>("get_Current").invoke();
        }
    }

    public static getCharacter():
        Il2Cpp.Object {

        const player = ObjectGetters.waitForPlayer();
        return player.method<Il2Cpp.Object>("get_Character").invoke();
    }

    public static waitForUi(): Il2Cpp.Object {
        const Client = Il2Cpp.domain.assembly("Client").image;
        const arr = Il2Cpp.gc.choose(Client.class("Assets.Core.Game.Battle.Gui.MainUI.MainUiContainer"))
        console.log("[CLIENT]Number of instances of Assets.Core.Game.Battle.Gui.MainUI.MainUiContainer ->", arr.length);
        for (let index = 0; index < arr.length; index++) {
            const element = arr[index];
            return element;
        }
        throw Error("MainUiContainer not found");
    }

}


class Controllor {
    public static async run(direction: DpadDirection, times: number = 1) {
        await wait(1000);
        await executeEvent("run", [direction, times]);
        await wait(1000);
    }
    public static async pressUse() {
        await executeEvent("use");
    }
    static async getRowColumnForItem(itemName: string, items: BackpackItemsWithIndex) {
        for (const key in items) {
            if (items[key].itemName === itemName) {
                const x = Number(key) % 5;
                const y = Math.floor(Number(key) / 5) + 1;
                return [x, y];
            }
        }
        return [null, null];
    }
    public static async dblClickOnCell(row: number, col: number) {
        await executeEvent("dbl_click_inventory", [row, col]);
    }

    public static async closePanel() {
        await executeEvent("close_inventory");
    }
    public static async pressAuto() {
        await executeEvent("auto")
    }
    public static async dblClickOnOutputCell() {
        await executeEvent("double_click_final_products")
    }
}

class Inventory {
    inventories: Il2Cpp.Object;
    character: Il2Cpp.Object;

    constructor(character: Il2Cpp.Object) {
        this.character = character;
        this.inventories = this.character.method<Il2Cpp.Object>("get_Inventories").invoke();
    }

    public getBackpackSpace() {
        return this.inventories.method<number>("CellsCount").invoke()
    }

    public getChestItems(): { items: BackpackItemsWithIndex, handler: Il2Cpp.Object } {
        const handler = ObjectGetters.getInventoryHandler();
        const ChestInventory = handler.field<Il2Cpp.Object>("_lootInventories").value;

        const partsList = ObjectGetters.listToGenerator(ChestInventory.method<Il2Cpp.Object>("get_InventoryParts").invoke())

        const ret: BackpackItemsWithIndex = {}
        let ItemIndex = 1;
        for (const parts of partsList) {
            // console.log(parts.method<Il2Cpp.String>("get_Id").invoke());

            const partsCellList = ObjectGetters.listToGenerator(parts.method<Il2Cpp.Object>("get_Cells").invoke())
            for (const cell of partsCellList) {
                // const ItemIndex = cell.method<number>("get_CellIndex").invoke() + 1
                if (!cell.method<Il2Cpp.Object>("IsEmpty").invoke()) {
                    const InventoryStack = cell.method<Il2Cpp.Object>("get_Stack").invoke()
                    const ItemName = InventoryStack.method<Il2Cpp.String>("get_Id").invoke().toString().replaceAll('"', "")
                    ret[ItemIndex] = { amount: InventoryStack.method<number>("GetAmount").invoke(), object: InventoryStack, itemName: ItemName }
                } else {
                    ret[ItemIndex] = { amount: 0, object: cell, itemName: "" }
                }
                ItemIndex++;
            }
        }
        return { items: ret, handler: handler };
    }

    public getBackpackItems(): [BackpackItems, number] {

        const partsList = ObjectGetters.listToGenerator(this.inventories.method<Il2Cpp.Object>("get_InventoryParts").invoke())

        const ret: BackpackItems = {}
        let NonEmptyCells = 0
        for (const parts of partsList) {
            // console.log(parts.method<Il2Cpp.String>("get_Id").invoke());

            const partsCellList = ObjectGetters.listToGenerator(parts.method<Il2Cpp.Object>("get_Cells").invoke())
            for (const cell of partsCellList) {
                if (!cell.method<Il2Cpp.Object>("IsEmpty").invoke()) {
                    const ItemIndex = cell.method<number>("get_CellIndex").invoke()
                    const InventoryStack = cell.method<Il2Cpp.Object>("get_Stack").invoke()
                    const ItemName = InventoryStack.method<Il2Cpp.String>("get_Id").invoke().toString().replaceAll('"', "")
                    if (ret[ItemName]) {
                        ret[ItemName] = { amount: ret[ItemName].amount + InventoryStack.method<number>("GetAmount").invoke(), object: [...ret[ItemName].object, InventoryStack] }
                    } else {
                        ret[ItemName] = { amount: InventoryStack.method<number>("GetAmount").invoke(), object: [InventoryStack] }
                    }
                    NonEmptyCells++;
                }
            }
        }
        return [ret, NonEmptyCells];
    }

    public getInventoryItemsAndIndex(): BackpackItemsWithIndex {

        const partsList = ObjectGetters.listToGenerator(this.inventories.method<Il2Cpp.Object>("get_InventoryParts").invoke())

        const ret: BackpackItemsWithIndex = {}
        for (const parts of partsList) {
            // console.log(parts.method<Il2Cpp.String>("get_Id").invoke());

            const partsCellList = ObjectGetters.listToGenerator(parts.method<Il2Cpp.Object>("get_Cells").invoke())
            for (const cell of partsCellList) {
                if (!cell.method<Il2Cpp.Object>("IsEmpty").invoke()) {
                    const ItemIndex = cell.method<number>("get_CellIndex").invoke() + 1
                    const InventoryStack = cell.method<Il2Cpp.Object>("get_Stack").invoke()
                    const ItemName = InventoryStack.method<Il2Cpp.String>("get_Id").invoke().toString().replaceAll('"', "")
                    ret[ItemIndex] = { amount: InventoryStack.method<number>("GetAmount").invoke(), object: cell, itemName: ItemName }
                }
            }
        }
        return ret;
    }
}

class Character {
    player: Il2Cpp.Object;
    character: Il2Cpp.Object;
    inventories: Inventory;

    constructor() {
        this.player = ObjectGetters.waitForPlayer();
        this.character = ObjectGetters.getCharacter();
        this.inventories = new Inventory(this.character);
    }
    public getHealth() {
        const Health = this.character.field<Il2Cpp.Object>("_health")?.value
        return Health.method<number>("GetAmount").invoke();
    }

    public heal() {
        this.character.method<void>("Heal").invoke(90);
    }

    public get_position() {
        return this.character.method<Il2Cpp.Object>("get_Position").invoke();
    }

    public async move(direction: DpadDirection) {
        this.character.method<void>("Move").invoke();
    }

    public async runFor(direction: DpadDirection, time: number) {
        // this.run(direction);
        await wait(time);
        console.log("[CLIENT][CLIENT]Stopping Player");
        const dpad = ObjectGetters.getDpad()
        dpad.method<void>("StopDpad").invoke();
    }

    public async runForTiles(direction: DpadDirection, tiles: number) {
        const TIME_FOR_ONE_TILE = 400;
        await this.runFor(direction, TIME_FOR_ONE_TILE * tiles);
    }
    public farmUntilFull() {
        return new Promise((resolve) => {
            const loop = setInterval(async () => {
                const currenthealth = this.getHealth();
                if (currenthealth < 50) this.heal();
                console.log("[CLIENT] Farming until full, Current health:", currenthealth);


                const [items, totalItems] = this.inventories.getBackpackItems()
                const AVAILABLE_ITEMS = Object.keys(items)

                const cellCount = this.inventories.getBackpackSpace();

                if (cellCount == totalItems) {
                    console.log("[CLIENT] Inventory is full we can move back home");
                    clearInterval(loop);
                    await executeEvent("auto");
                    resolve(true);
                }




                // console.log(Object.keys(items));
                if (!AVAILABLE_ITEMS.includes("pickaxe")) {
                    console.log("[CLIENT] Pickaxe not found we should craft it");
                    if (AVAILABLE_ITEMS.includes("wood") && AVAILABLE_ITEMS.includes("stone") && items["wood"].amount >= 3 && items["stone"].amount >= 3) {
                        await executeEvent("craft_button");
                        await wait(1000);
                        await executeEvent("craft_item", ["pickaxe"]);
                        await wait(1000);
                        await executeEvent("close_inventory");
                        await wait(1000);
                    }
                }
                if (!Object.keys(items).includes("hatchet")) {
                    console.log("[CLIENT] Hatchet not found we should craft it");
                    if (AVAILABLE_ITEMS.includes("wood") && AVAILABLE_ITEMS.includes("stone") && items["wood"].amount >= 3 && items["stone"].amount >= 3) {
                        await executeEvent("craft_button");
                        await wait(1000);
                        await executeEvent("craft_item", ["hatchet"]);
                        await wait(1000);
                        await executeEvent("close_inventory");
                        await wait(1000);
                    }
                }

                console.log("[CLIENT] Farming until full end of loop");
            }, 2000);
        });
    }

    public teleport(x: number, y: number, z: number) {
    // const playerRotationVector3 = this.character.method<Il2Cpp.Object>("get_Rotation").invoke();
    // this.character.method<void>("Move").invoke(playerPositionVector3, playerRotationVector3, true, false);

        const playerPositionVector3 = this.character.method<Il2Cpp.Object>("get_Position").invoke();
        playerPositionVector3.field<number>("x").value = x;
        playerPositionVector3.field<number>("y").value = y;
        playerPositionVector3.field<number>("z").value = z;
        this.character.method<void>("SetPosition").invoke(playerPositionVector3, true, false);
    }

    public async moveToLocation(name: LocationNames) {
        const Client = Il2Cpp.domain.assembly("Client").image;

        const map = ObjectGetters.getMap();
        const location = ObjectGetters.getLocationDescriptionFor(name);
        map.method<Il2Cpp.Object>("MoveToPoint").invoke(location);

        console.log("[CLIENT] Now we can wait for player to reach the location");
        await wait(12.1 * 60 * 1000);
        // Enter location
        const GlobalMapPlayerModelView = Client.class("Assets.Core.Game.GlobalMap.GlobalMapPlayerModelView");
        const arr = Il2Cpp.gc.choose(GlobalMapPlayerModelView);
        console.log("[CLIENT]Number Assets.Core.Game.GlobalMap.Models.GlobalMapLocationDescription ->", arr.length);
        for (let index = 0; index < arr.length; index++) {
            const element = arr[index];
            element.method<void>("EnterLocation").invoke();
        }
        await wait(10000);
    }

    public async putItemsForProcessing(itemNames: string[], tableLocation: Location, pickProcessed = false) {

        const items = this.inventories.getInventoryItemsAndIndex();

        this.teleport(LOCATIONS[tableLocation][0], LOCATIONS[tableLocation][1], LOCATIONS[tableLocation][2])
        await wait(3000);
        await Controllor.pressUse();
        await wait(2000);


        for (let index = 0; index < itemNames.length; index++) {
            const itemName = itemNames[index];
            const [row, col] = await Controllor.getRowColumnForItem(itemName, items);
            if (row && col) {
                await Controllor.dblClickOnCell(row, col);
                await wait(2000);
            }
        }

        if (pickProcessed) {
            await Controllor.dblClickOnOutputCell();
        }

        await wait(1000);
        await Controllor.closePanel();
        await wait(2000);
    }
}


const CHEST_LOCATIONS = {
    "CHEST_1": [12.23, 0.21, -3.02],
    "CHEST_2": [12.33, 0.21, -5.05],
    "CHEST_3": [12.43, 0.21, -7.05],
    "CHEST_4": [12.47, 0.21, -9.17],
    "CHEST_5": [12.24, 0.21, -11.16],
}
const LOCATIONS = {
    HOME_MAP_TOP_RIGHT: [19.72, 0.01, -19.88],
    TREES_MAP_TOP_RIGHT: [29.86, 0.01, -30.00],
    FARM_LAND_1: [-10.00, 0.01, -0.29],
    FARM_LAND_2: [-10.06, 0.01, 3.50],
    WORKBENCH_1: [12.27, 0.21, 0.82],
    WORKBENCH_2: [12.28, 0.21, -0.98],
    CAMPFIRE_1: [16.14, 0.01, -2.97],
    CAMPFIRE_2: [16.14, 0.01, -5.08],
}
type ChestLocation = keyof typeof CHEST_LOCATIONS;
type Location = keyof typeof LOCATIONS;
const executeEvent = (event: ControlEvents, args: (number | string)[] = []) => {
    return new Promise((resolve) => {
        // console.log("[CLIENT] Executing Event", event, args);
        send({ event: event, args: args });
        recv(event, () => {
            // console.log("[CLIENT] Event Executed", event);
            resolve(true);
        });
    });
}


const start = () => {
    return new Promise((resolve) => {
        Il2Cpp.perform(async () => {
            const player = new Character();

            // player.teleport(LOCATIONS.HOME_MAP_TOP_RIGHT[0], LOCATIONS.HOME_MAP_TOP_RIGHT[1], LOCATIONS.HOME_MAP_TOP_RIGHT[2]);
            // await wait(3000);
            // await Controllor.run("WD", 5);
            // await wait(10000);
            // await player.moveToLocation("Trees_01_1");

            // await executeEvent("auto");
            // await player.farmUntilFull();

            // player.teleport(LOCATIONS.TREES_MAP_TOP_RIGHT[0], LOCATIONS.TREES_MAP_TOP_RIGHT[1], LOCATIONS.TREES_MAP_TOP_RIGHT[2]);
            // await wait(3000);
            // await Controllor.run("WD", 5);
            // await wait(10000);
            // await player.moveToLocation("home");

            const keys = Object.keys(CHEST_LOCATIONS)
            // const items = player.inventories.getInventoryItemsAndIndex();
            // const [allItems, totalItems] = player.inventories.getAllItems();
            // console.log("[CLIENT] All Items", Object.keys(allItems));

            // await player.putItemsForProcessing(["wood"], "WORKBENCH_1", true);
            // await player.putItemsForProcessing(["wood"], "WORKBENCH_2", true);



            // await player.putItemsForProcessing(["resource_charcoal", "resource_plank_1"], "CAMPFIRE_1", true);
            await player.putItemsForProcessing(["resource_charcoal", "resource_plank_1"], "CAMPFIRE_2", true);
            // await player.putItemsForProcessing(["wood", "resource_plank_1"], "WORKBENCH_1", items);

            // for (let index = 0; index < keys.length; index++) {
            //     const key = keys[index];

            //     const location = CHEST_LOCATIONS[key as ChestLocation];
            //     player.teleport(location[0], location[1], location[2]);
            //     await wait(3000);
            //     await executeEvent("use");
            //     await wait(2000);
            //     await executeEvent("put_all");
            //     await wait(2000);
            //     await executeEvent("close_inventory");
            //     await wait(1000);
            // }


            resolve("done");
        });
    });
}

const test = () => {
    return new Promise((resolve) => {
        Il2Cpp.perform(async () => {


            // const Client = Il2Cpp.domain.assembly("Client").image;

            const player = new Character();
            // console.log("[CLIENT] Health", player.getHealth());
            const { items: ChestItems, handler } = player.inventories.getChestItems();
            const [PlayerItems, _] = player.inventories.getBackpackItems();

            console.log(Object.keys(PlayerItems));

            handler.method<void>("OnDoubleClick").invoke(PlayerItems["thick_hat_fortified"].object[0], ChestItems["25"].object);

            // for (const key in ChestItems) {
            //     console.log(ChestItems[key].itemName, key);
            //     // handler.method<void>("TakeItem").invoke(items[key].object);

            // }
            // console.log(items);

            // const obj = ObjectGetters.getInventoryHandler();
            // const ChestInventory = obj.field<Il2Cpp.Object>("_lootInventories").value;


            // console.log(ChestInventory.method("CellsCount").invoke(), "sds");
            // console.log(ChestInventory.method<Il2Cpp.Object>("get_InventoryParts").invoke(), "sds");
            // ObjectGetters.listToGenerator(ChestInventory.method<Il2Cpp.Object>("get_InventoryParts").invoke()).next();
            // console.log(obj.method<Il2Cpp.Object>("OnDoubleClick").invoke());

            // const [items, _] = player.inventories.getAllItems()
            // console.log(Object.keys(items));
            // for (const key in items) {

            //     if (items[key].itemName === "wood" && items[key].amount > 15) {
            //         const [row, col] = cellIndexToCords(Number(key));
            //         await executeEvent("dbl_click_inventory", [String(row), String(col)]);
            //     }
            // }

            // await executeEvent("double_click_final_products");
            // console.log("[CLIENT]Number Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController ->", arr1.length);


            // const player = new Character();
            const position = player.get_position();
            console.log("[CLIENT] Position", position);
            // send({ event: "position", data: position });
            resolve(true);
        });
    })
}



rpc.exports = {
    test: test,
    start: start,
}