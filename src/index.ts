import "frida-il2cpp-bridge";
import * as fs from "fs";
import * as path from "path";
console.log("Frida Loaded Successfully");

const TIMEOUT = 30000; // 30 seconds

type DpadDirection = "w" | "a" | "s" | "d" | "wa" | "wd" | "sa" | "sd" | "stop";

const wait = (time: number) => new Promise((resolve) => setTimeout(resolve, time));
class ObjectGetters {

    public static getDpad() {
        const ui = ObjectGetters.waitForUi();
        const dpad = ui.field<Il2Cpp.Object>("DpadController")?.value;
        if (!dpad) throw Error("dpad is null");
        return dpad;
    }

    public static waitForPlayer(): 
        Il2Cpp.Object
    {
        const Client = Il2Cpp.domain.assembly("Client").image;

        const PlayerClass = Client.class("Assets.Core.Models.Users.Player");

        const arr = Il2Cpp.gc.choose(PlayerClass)
        console.log("Number of instances of Assets.Core.Models.PlayerClass ->", arr.length);

        for (let index = 0; index < arr.length; index++) {
            const element = arr[index];
            return element;
        }
        throw Error("PlayerObject not found");

    }
    public static getCharacter():
        Il2Cpp.Object {

        const player = ObjectGetters.waitForPlayer();
        return player.method<Il2Cpp.Object>("get_Character").invoke();
    }

    public static waitForUi(): Il2Cpp.Object {
        const Client = Il2Cpp.domain.assembly("Client").image;
        const arr = Il2Cpp.gc.choose(Client.class("Assets.Core.Game.Battle.Gui.MainUI.MainUiContainer"))
        console.log("Number of instances of Assets.Core.Game.Battle.Gui.MainUI.MainUiContainer ->", arr.length);
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
        console.log("AutoUseController", arr.length);
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

    constructor() {
        this.player = ObjectGetters.waitForPlayer();
        this.character = ObjectGetters.getCharacter();
    }
    public getHealth() {
        const Health = this.player.tryField<Il2Cpp.Object>("_health")?.value
        if (!Health) throw Error("Health is null");
        return Health.method<number>("GetAmount").invoke();
    }

    public getInventorySpace() {
        const Inventories = this.player.method<Il2Cpp.Object>("get_Inventories").invoke();
        return Inventories.method<number>("CellsCount").invoke()
    }
    public heal() {
        this.character.method<void>("Heal").invoke(90);
    }

    public async get_position() {
        return this.character.method<Il2Cpp.Object>("get_Position").invoke();
    }

    public async move(direction: DpadDirection) {
        this.character.method<void>("Move").invoke();
    }

    public async runFor(direction: DpadDirection, time: number) {
        this.run(direction);
        await wait(time);
        console.log("Stopping Player");
        const dpad = ObjectGetters.getDpad()
        dpad.method<void>("StopDpad").invoke();
    }

    public async runForTiles(direction: DpadDirection, tiles: number) {
        const TIME_FOR_ONE_TILE = 400;
        await this.runFor(direction, TIME_FOR_ONE_TILE * tiles);
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
        // console.log(dpad.class);
        const method = dpad.method<void>("Run");
        // Il2Cpp.delegate("UnityEngine.Events.UnityAction")
        // console.log(method.parameters[1].name);
        // method.invoke(vector, 1);
        // Il2Cpp.corlib
    }
    // public async clickOn(button: "attack" | "auto" | "use" | "take_all" | "put_all" | "close_inventory", time: number = 100) {
    //     if (button === "attack") {
    //         const attackController = ObjectGetters.getAttackController();
    //         attackController.method<void>("OnDown").invoke(this.pointerEvent)
    //         await wait(time);
    //         attackController.method<void>("OnUp").invoke(this.pointerEvent)
    //     }

    //     if (button === "auto") {
    //         const autoUseController = ObjectGetters.getAutoController();
    //         autoUseController.method<void>("OnDown").invoke(this.pointerEvent)
    //         await wait(time);
    //         autoUseController.method<void>("OnUp").invoke(this.pointerEvent)
    //     }
    //     if (button === "use") {
    //         const useController = ObjectGetters.getUseButtonController();
    //         useController.method<void>("OnDown").invoke(this.pointerEvent)
    //         await wait(time);
    //         useController.method<void>("OnUp").invoke(this.pointerEvent)
    //     }
    //     if (button === "take_all") {
    //         const InventoryUi = ObjectGetters.getInventoryUI();
    //         const take_all_button = InventoryUi.field<Il2Cpp.Object>("TakeAllButton").value
    //         take_all_button.method<void>("OnDown").invoke(this.pointerEvent)
    //         await wait(time);
    //         take_all_button.method<void>("OnUp").invoke(this.pointerEvent)
    //     }
    //     if (button === "put_all") {
    //         const InventoryUi = ObjectGetters.getInventoryUI();
    //         const put_all_button = InventoryUi.field<Il2Cpp.Object>("PutAllButton").value
    //         put_all_button.method<void>("OnDown").invoke(this.pointerEvent)
    //         await wait(time);
    //         put_all_button.method<void>("OnUp").invoke(this.pointerEvent)
    //     }

    //     if (button === "close_inventory") {
    //         const InventoryUi = ObjectGetters.getInventoryUI();
    //         const close = InventoryUi.field<Il2Cpp.Object>("CloseButton").value
    //         close.method<void>("Press").invoke()
    //         await wait(time);
    //         // close.method<void>("OnUp").invoke(pointerEvent)
    //     }
    // }

    public teleport(x: number, y: number, z: number) {
    // const playerRotationVector3 = this.character.method<Il2Cpp.Object>("get_Rotation").invoke();
    // this.character.method<void>("Move").invoke(playerPositionVector3, playerRotationVector3, true, false);

        const playerPositionVector3 = this.character.method<Il2Cpp.Object>("get_Position").invoke();
        playerPositionVector3.field<number>("x").value = x;
        playerPositionVector3.field<number>("y").value = y;
        playerPositionVector3.field<number>("z").value = z;
        this.character.method<void>("SetPosition").invoke(playerPositionVector3, true, false);
    }

    public async getAllInventories() {
        // ObjectGetters.getAllInventories();
        ObjectGetters.getAutoController();
    }
}


const LOCATIONS = {
    "CHEST_1": [-7.09, 0.21, -11.84],
    "CHEST_2": [-5.04, 0.21, -11.75],
    "CHEST_3": [-3.07, 0.21, -11.74],
    "CHEST_4": [-1.08, 0.21, -11.76],
    "CHEST_5": [0.74, 0.21, -11.58],
}
type Location = keyof typeof LOCATIONS;

const click = () => {
    return new Promise((resolve) => {
        Il2Cpp.perform(async () => {
            const player = new Character();

            const keys = Object.keys(LOCATIONS)

            for (let index = 0; index < keys.length; index++) {
                const key = keys[index];

                const location = LOCATIONS[key as Location];
                player.teleport(location[0], location[1], location[2]);
                await wait(3000);

            }
            resolve("done");
        });
    });
}

const start = () => {
    return new Promise((resolve) => {
        Il2Cpp.perform(async () => {

            const player = new Character();
            const Client = Il2Cpp.domain.assembly("Client").image;
            const arr = Il2Cpp.gc.choose(Client.class("Assets.Core.Models.Users.LocationObject.LocationObjectModel"))
            console.log(arr.length, "LocationObjectModel");

            for (let index = 0; index < arr.length; index++) {
                const element = arr[index];
                // @ts-ignore
                const uid = String(element.method<Il2Cpp.Object>("get_LocationObjectId").invoke()).replaceAll('"', "");
                console.log(uid);
                if (uid === "") {
                    try {
                        const use = player.character.method<boolean>("CallUse").invoke(element);
                        console.log(element, use);
                    }
                    catch (error) {
                        console.log("Error", error);
                    }
                }
            }
            resolve("done");
        });
    });
}



rpc.exports = {
    click: click,
    start: start
}