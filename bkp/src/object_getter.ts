import { LocationNames } from "./types";
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
        Il2Cpp.Object {
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


export default ObjectGetters;