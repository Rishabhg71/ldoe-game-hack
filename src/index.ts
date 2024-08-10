import "frida-il2cpp-bridge";
import * as fs from "fs";
import * as path from "path";
console.log("[CLIENT]Frida Loaded Successfully");

const TIMEOUT = 30000; // 30 seconds

type DpadDirection = "w" | "a" | "s" | "d" | "wa" | "wd" | "sa" | "sd" | "stop";
type ControlEvents = "attack" | "auto" | "use" | "take_all" | "put_all" | "close_inventory" | "run" | "craft_button" | "craft_item" | "dbl_click_inventory";
type LocationNames = "home" | "Trees_01_1";
type BackpackItems = {
    [key: string]: { amount: number, object: Il2Cpp.Object[] },
};
type BackpackItemsWithIndex = {
    [key: number]: { amount: number, object: Il2Cpp.Object, itemName: string },
};


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

    static getAllInventories() {
        const Client = Il2Cpp.domain.assembly("Client").image;
        // const chestClass = Client.tryClass("Assets.Core.Game.Battle.Gui.InventoryUI.InventoryUiController")
        // const chestClass = Client.tryClass("Assets.Core.Models.InventoryModels.Inventories")
        const chestClass = Client.tryClass("Assets.Core.Sync.Views.Inventories.ChestInventoryView")
        if (!chestClass) throw Error("Inventories not found");

        const arr = Il2Cpp.gc.choose(chestClass);
        console.log(arr.length);
        for (let index = 0; index < arr.length; index++) {
            const element = arr[index];
            // element.method<void>("Show").invoke();
        }
    }

    static getPointerEvent() {
        const PointerEventData = Il2Cpp.domain.assembly("UnityEngine.UI").image.class("UnityEngine.EventSystems.PointerEventData");
        const pointerArr = Il2Cpp.gc.choose(PointerEventData);
        for (let index = 0; index < pointerArr.length; index++) {
            const element = pointerArr[index];
            return element;
        }
        throw Error("PointerEvent not found");
    }

    static getAutoController() {
        const Client = Il2Cpp.domain.assembly("Client").image;
        const AutoUseController = Client.class("Assets.Core.Game.Battle.Gui.MainUI.Buttons.AutoUseController")

        const arr = Il2Cpp.gc.choose(AutoUseController);
        console.log("[CLIENT][CLIENT]AutoUseController", arr.length);
        for (let index = 0; index < arr.length; index++) {
            const element = arr[index];
            return element;
            // element.method<void>("OnDown").invoke();
        }
        throw Error("AutoUseController not found");
    }

    static getUseButtonController() {
        const Client = Il2Cpp.domain.assembly("Client").image;
        const UseController = Client.class("Assets.Core.Game.Battle.Gui.MainUI.Buttons.UseController")

        const arr = Il2Cpp.gc.choose(UseController);
        console.log(arr.length);
        for (let index = 0; index < arr.length; index++) {
            const element = arr[index];
            return element;
            // element.method<void>("OnDown").invoke();
        }
        throw Error("UseController not found");
    }

    static getAttackController() {
        const Client = Il2Cpp.domain.assembly("Client").image;
        const AttackController = Client.class("Assets.Core.Game.Battle.Gui.MainUI.Buttons.AttackController")

        const arr = Il2Cpp.gc.choose(AttackController);
        console.log(arr.length);
        for (let index = 0; index < arr.length; index++) {
            const element = arr[index];
            return element;
        }
        throw Error("AttackController not found");
    }

    public static getInventoryUI() {
        const Client = Il2Cpp.domain.assembly("Client").image;
        const InventoryUiContainer = Client.class("Assets.Core.Game.Battle.Gui.InventoryUI.InventoryUiContainer")

        const arr = Il2Cpp.gc.choose(InventoryUiContainer);
        for (let index = 0; index < arr.length; index++) {
            const element = arr[index];
            return element;
        }
        console.log('InventoryUiContainer not found');
        throw Error("InventoryUiContainer not found");
    }

}


class Character {
    player: Il2Cpp.Object;
    character: Il2Cpp.Object;
    inventories: Il2Cpp.Object;

    constructor() {
        this.player = ObjectGetters.waitForPlayer();
        this.character = ObjectGetters.getCharacter();
        this.inventories = this.character.method<Il2Cpp.Object>("get_Inventories").invoke();
    }
    public getHealth() {
        const Health = this.character.field<Il2Cpp.Object>("_health")?.value
        return Health.method<number>("GetAmount").invoke();
    }

    public getBackpackSpace() {
        return this.inventories.method<number>("CellsCount").invoke()
    }
    public getInventoryItems(): [BackpackItems, number] {

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
                    ret[ItemIndex] = { amount: InventoryStack.method<number>("GetAmount").invoke(), object: InventoryStack, itemName: ItemName }
                }
            }
        }
        return ret;
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
        this.run(direction);
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


                const [items, totalItems] = this.getInventoryItems()
                const AVAILABLE_ITEMS = Object.keys(items)

                const cellCount = this.inventories.method<number>("CellsCount").invoke()

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

    public run(direction: DpadDirection) {
        const dpad = ObjectGetters.getDpad()

        // const UnityEngine = Il2Cpp.domain.assembly("UnityEngine").image;
        // let Vector2 = UnityEngine.class("UnityEngine.Vector2").alloc();
        // Vector2.method<void>("Set").invoke(0.5, 0.5);
        // Vector2 = Vector2.method<Il2Cpp.Object>("get_normalized").invoke()

        let cords = [0.0, 0.0];
        if (direction === "w") cords = [0.0, 1.0];
        if (direction === "a") cords = [-1.0, 0.0];
        if (direction === "s") cords = [0.0, -1.0];
        if (direction === "d") cords = [1.0, 0.0];
        if (direction === "wa") cords = [-1.0, 1.0];
        if (direction === "wd") cords = [1.0, 1.0];
        if (direction === "sa") cords = [-1.0, -1.0];
        if (direction === "sd") cords = [1.0, -1.0];
        if (direction === "stop") cords = [0, 0];

        const vector = dpad.field<Il2Cpp.Object>("_defaultPos").value;
        vector.method<void>("Set").invoke(cords[0], cords[1]);
        const method = dpad.method<void>("Run");
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

    public getAllInventories() {
        // ObjectGetters.getAllInventories();
        ObjectGetters.getAutoController();
    }

    public async moveToLocation(name: LocationNames) {
        const Client = Il2Cpp.domain.assembly("Client").image;

        const map = ObjectGetters.getMap();
        const location = ObjectGetters.getLocationDescriptionFor(name);
        map.method<Il2Cpp.Object>("MoveToPoint").invoke(location);

        await wait(12.1 * 60 * 1000);
        // Enter location
        const GlobalMapPlayerModelView = Client.class("Assets.Core.Game.GlobalMap.GlobalMapPlayerModelView");
        const arr = Il2Cpp.gc.choose(GlobalMapPlayerModelView);
        console.log("[CLIENT]Number Assets.Core.Game.GlobalMap.Models.GlobalMapLocationDescription ->", arr.length);
        for (let index = 0; index < arr.length; index++) {
            const element = arr[index];
            element.method<void>("EnterLocation").invoke();
        }
    }
}


const CHEST_LOCATIONS = {
    "CHEST_1": [-7.09, 0.21, -11.84],
    "CHEST_2": [-5.04, 0.21, -11.75],
    "CHEST_3": [-3.07, 0.21, -11.74],
    "CHEST_4": [-1.08, 0.21, -11.76],
    "CHEST_5": [0.74, 0.21, -11.58],
}
const LOCATIONS = {
    HOME_MAP_TOP_RIGHT: [19.72, 0.01, -19.88],
    TREES_MAP_TOP_RIGHT: [29.86, 0.01, -30.00],
}
type ChestLocation = keyof typeof CHEST_LOCATIONS;
type Location = keyof typeof LOCATIONS;

const executeEvent = (event: ControlEvents, args: string[] = []) => {
    return new Promise((resolve) => {
        console.log("[CLIENT] Executing Event", event);
        send({ event: event, args: args });
        recv(event, () => {
            console.log("[CLIENT] Event Executed", event);
            resolve(true);
        });
    });
}

const start = () => {
    return new Promise((resolve) => {
        Il2Cpp.perform(async () => {
            const player = new Character();

            const keys = Object.keys(CHEST_LOCATIONS)

            for (let index = 0; index < keys.length; index++) {
                const key = keys[index];

                const location = CHEST_LOCATIONS[key as ChestLocation];
                player.teleport(location[0], location[1], location[2]);
                await wait(3000);
                await executeEvent("use");
                await wait(2000);
                await executeEvent("put_all");
                await wait(2000);
                await executeEvent("close_inventory");
                await wait(1000);
            }
            player.teleport(LOCATIONS.HOME_MAP_TOP_RIGHT[0], LOCATIONS.HOME_MAP_TOP_RIGHT[1], LOCATIONS.HOME_MAP_TOP_RIGHT[2]);
            await wait(3000);
            await executeEvent("run", ["WD", "5"]);
            await wait(3000);
            await player.moveToLocation("Trees_01_1");
            console.log("[CLIENT] Now we can wait for player to reach the location");

            await executeEvent("auto");
            await player.farmUntilFull();

            player.teleport(LOCATIONS.TREES_MAP_TOP_RIGHT[0], LOCATIONS.TREES_MAP_TOP_RIGHT[1], LOCATIONS.TREES_MAP_TOP_RIGHT[2]);
            await wait(3000);
            await executeEvent("run", ["WD", "5"]);
            await wait(10000);
            await player.moveToLocation("home");


            resolve("done");
        });
    });
}

const test = () => {
    return new Promise((resolve) => {
        Il2Cpp.perform(async () => {


            // const Client = Il2Cpp.domain.assembly("Client").image;

            const player = new Character();
            console.log("[CLIENT] Health", player.getHealth());

            const items = player.getInventoryItemsAndIndex()
            // console.log(Object.keys(items));
            for (const key in items) {
                if (items[key].itemName === "resource_plank_1" && items[key].amount > 15) {
                    await executeEvent("dbl_click_inventory", [key]);
                    console.log("resource_plank_1", key);
                }
            }
            // console.log("[CLIENT]Number Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController ->", arr1.length);


            // const player = new Character();
            // const position = player.get_position();
            // console.log("[CLIENT] Position", position);
            // send({ event: "position", data: position });
            resolve(true);
        });
    })
}

rpc.exports = {
    test: test,
    start: start,
}