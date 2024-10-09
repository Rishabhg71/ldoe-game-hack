import "frida-il2cpp-bridge";
import * as fs from "fs";
import * as path from "path";

Il2Cpp.perform(() => {
    try {
        console.log("Starting the script");
        // Il2Cpp.trace(true).domain().filterClasses((kclass) => kclass.fullName.includes("Inventory")).filterMethods((method) => {
        //     // if (method.name === "OnPointerUp") return true;
        //     // if (method.name === "OnPointerDown") return true;
        //     // if (method.name === "OnPointerEnter") return true;
        //     if (method.name === "HandleDoubleClick") return true;
        //     return false;
        // }).and().attach();
        let trace = true;

        // const targetClass = Il2Cpp.domain.assembly("Client").image.class("Assets.Core.Game.Dialogs.Inventory.InventoryHandler"); // Replace with the target class name
        // targetClass.method<void>("OnDoubleClick").implementation = function (...args) {
        //     trace = true;
        //     console.log("OnDoubleClick");

        //     return this.method<void>("OnDoubleClick").invoke(...args);
        // }

        Il2Cpp.trace(false).domain().filterClasses((klass) => {
            // if (klass.fullName.includes("Workbench")) return true;
            if (klass.fullName.includes("Cell")) return true;
            // if (klass.fullName.includes("Inventory")) return true;

            // if (klass.fullName.includes("WorkbenchInventoryStackReward")) return false;
            // if (klass.fullName.includes("WorkbenchHasFreeSkipsRequirement")) return false;
            // if (klass.fullName.includes("Assets.Core.Game.Dialogs.Inventory.StatsDialog")) return false;
            // if (klass.fullName.includes("Assets.Core.Game.Dialogs.Inventory.HungryLabelComponent")) return false;
            // if (klass.fullName.includes("InventoryCellController")) return false;
            return true;
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
            if (method.name === "SetRaycastActive") return false;


            if (method.name === "SetActive") return false;
            if (method.name === "get_IsInitialized") return false;
            if (method.name === "get_Stack") return false;
            if (method.name === "get_Recipes") return false;
            if (method.name === "get_RecipesTimeModifier") return false;
            return true;
        }).and().attach();
    } catch (e) {
        console.log(e);
    }
});

// Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_Inventories
// Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::Add


// Perform the tracing for a specific method
// Il2Cpp.perform(() => {

//     // const targetClass = Il2Cpp.domain.assembly("Client").image.class("Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell"); // Replace with the target class name
//     // const targetMethod = targetClass.method("Add"); // Replace with the target method name
//     // Il2Cpp.backtrace(Backtracer.FUZZY).methods(targetMethod).and().attach();

//     const targetClass = Il2Cpp.domain.assembly("Client").image.class("Assets.Core.Game.Dialogs.Inventory.InventoryHandler"); // Replace with the target class name
// });