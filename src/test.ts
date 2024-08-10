import "frida-il2cpp-bridge";
import * as fs from "fs";
import * as path from "path";


Il2Cpp.perform(() => {
    try {

        Il2Cpp.trace(true).domain().filterClasses((klass) => {
            // if (klass.fullName.includes("Workbench")) return true;
            // if (klass.fullName.includes("Cell")) return true;
            if (klass.fullName.includes("Inventory")) return true;

            if (klass.fullName.includes("WorkbenchInventoryStackReward")) return false;
            if (klass.fullName.includes("WorkbenchHasFreeSkipsRequirement")) return false;
            if (klass.fullName.includes("Assets.Core.Game.Dialogs.Inventory.StatsDialog")) return false;
            if (klass.fullName.includes("Assets.Core.Game.Dialogs.Inventory.HungryLabelComponent")) return false;
            // if (klass.fullName.includes("InventoryCellController")) return false;
            return false;
        }).filterMethods((method) => {
            if (method.name === "UpdateMovement") return false;
            if (method.name === "OnTicked") return false;
            if (method.name === "OnTick") return false;
            if (method.name === "get_TsNow") return false;
            if (method.name === "Update") return false;
            if (method.name === "OnZoomChanged") return false;
            if (method.name === "OnUpdate") return false;
            if (method.name === "UserModelOnUpdated") return false;
            if (method.name === "InnerUpdate") return false;
            if (method.name === "SetFogDistanceScale") return false;
            if (method.name === "SetGlobalMapFog") return false;
            if (method.name === "Locate") return false;
            if (method.name === "get_InsideHomeLocation") return false;
            if (method.name === "remove_OnClick") return false;
            if (method.name === "remove_Changed") return false;
            if (method.name === "OnThirstChanged") return false;
            if (method.name === "OnHungerChanged") return false;
            if (method.name === "get_Tag") return false;
            if (method.name === "IsEmpty") return false;
            if (method.name === "remove_InventoryChanged") return false;
            if (method.name === "add_InventoryChanged") return false;
            if (method.name === "remove_InventoryChange") return false;
            if (method.name === "add_InventoryChange") return false;
            if (method.name === "UpdateWorkbench") return false;
            if (method.name === "UpdateRadDefence") return false;
            if (method.name === "UpdateHunger") return false;
            if (method.name === "UpdateThirst") return false;
            if (method.name === "CheckAward") return false;
            if (method.name === ".ctor") return false;
            if (method.name === "Generate") return false;
            if (method.name === "Check") return false;
            if (method.name === "CheckPlaceStack") return false;
            if (method.name === "CheckActive") return false;
            if (method.name === "OnPointerExit") return false;
            if (method.name === "OnPointerClick") return false;
            if (method.name === "OnPointerUp") return false;
            if (method.name === "OnPointerDown") return false;
            if (method.name === "OnPointerEnter") return false;


            if (method.name === "get_Stack") return false;
            if (method.name === "get_Recipes") return false;
            if (method.name === "get_RecipesTimeModifier") return false;
            return true;
        }).and().attach();
    } catch (e) {
        console.log(e);
    }
});



const pingPong = () => {
    Il2Cpp.perform(() => {

        // send({ event: "use" });
        console.log("[CLIENT] Listening for message");
        send({ event: "pokeFrom" });
        recv("poke", () => {
            console.log("[CLIENT] Event Executed", "use");
        }).wait();
    });
}