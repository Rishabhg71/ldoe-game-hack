import "frida-il2cpp-bridge";

console.log("Frida Loaded Successfully");

const TIMEOUT = 30000; // 30 seconds

// console.log("Loaded modules:");
// Process.enumerateModules().forEach(module => {
//     console.log(module.name);
// });





Il2Cpp.perform(() => {
    console.log("libil2cpp.so loaded, performing Il2Cpp operations...", Il2Cpp.unityVersion);

    // const AssemblyCSharp = Il2Cpp.domain.assembly("Assembly-CSharp").image;
    // const GlobalMap = AssemblyCSharp.class("Assets.Core.Game")

    const Client = Il2Cpp.domain.assembly("Client").image;


    const PlayerInventoriesModel = Client.class("Assets.Core.Models.PlayerInventories.PlayerInventoriesModel")
    const AutoUseController = Client.class("Assets.Core.Game.Battle.Gui.MainUI.Buttons.AutoUseController")
    const UiSwithButtonController = Client.class("Assets.Core.Game.Battle.Gui.MainUI.Buttons.UiSwithButtonController")


    let fakeEvent: Il2Cpp.Parameter.Type | null = null
    let AutoBtn: Il2Cpp.Class | Il2Cpp.ValueType | Il2Cpp.Object | null = null
    AutoUseController.parent ? AutoUseController.parent.method<void>("OnDown").implementation = function (eventData): void {
        console.log(`Auto Btn pressed`);
        fakeEvent = eventData
        AutoBtn = this
        this.method<void>("OnDown").invoke(eventData);
    } : console.log("No parent found for AutoUseController");





    Il2Cpp.trace(true).classes(
        // GlobalMap,
        // InventoryHandler,
        // InventoryUI
    ).and().attach();

    Il2Cpp.trace(true).methods(
        // InventoryHandler.method("OnDoubleClick")
    ).and().attach();
});
