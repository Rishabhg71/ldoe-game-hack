import "frida-il2cpp-bridge";
import * as fs from 'fs';
import * as path from 'path';


console.log("Frida Loaded Successfully");

const TIMEOUT = 30000; // 30 seconds

// console.log("Loaded modules:");
// Process.enumerateModules().forEach(module => {
//     console.log(module.name);
// });

const waitForPlayer = (
    // player: Il2Cpp.Class | Il2Cpp.ValueType | Il2Cpp.Object | null
): Promise<Il2Cpp.Class | Il2Cpp.ValueType | Il2Cpp.Object> => {

    const Client = Il2Cpp.domain.assembly("Client").image;

    const PlayerClass = Client.class("Assets.Core.Models.Users.Player");

    let PlayerObject: Il2Cpp.Class | Il2Cpp.ValueType | Il2Cpp.Object | null = null;
    PlayerClass.method("get_TimeNow").implementation = function () {
        if (!PlayerObject) PlayerObject = this;
        // console.log("Just logging");
        return this.method("get_TimeNow").invoke();
    };


    return new Promise((resolve, reject) => {
        setInterval(() => {
            if (PlayerObject) resolve(PlayerObject);
            else console.log("Waiting for PlayerObject");
        }, 2000);
    });
};

Il2Cpp.perform(() => {
    console.log(
        "libil2cpp.so loaded, performing Il2Cpp operations...",
        Il2Cpp.unityVersion
    );
    try {
        // const AssemblyCSharp = Il2Cpp.domain.assembly("Assembly-CSharp").image;
        // const GlobalMap = AssemblyCSharp.class("Assets.Core.Game")

        const Client = Il2Cpp.domain.assembly("Client").image;

        const PlayerInventoriesModel = Client.class("Assets.Core.Models.PlayerInventories.PlayerInventoriesModel")
        const PlayerClass = Client.class("Assets.Core.Models.Users.Player");
        const BackpackInventoryController = Client.class("Assets.Core.Sync.Controllers.Inventories.BaseInventoryController");
        const Inventories = Client.class("Assets.Core.Models.InventoryModels.Inventories");

        waitForPlayer().then((player) => {
            const inventory = player.method<Il2Cpp.Object>("get_PlayerInventories").invoke();
            const ref = inventory.ref(true);

            // inv.weakRef(true).target.
            const inventoryEnum = inventory.method<Il2Cpp.Object>("GetEnumerator").invoke();
            // System.Collections.IEnumerator.get_Current
            // System.Collections.IDictionaryEnumerator.get_Value

            // while (inventoryEnum.method<boolean>("MoveNext").invoke()) {
            //     const current = inventoryEnum.method<Il2Cpp.Object>("get_Current").invoke();
            //     // const value = current.method<Il2Cpp.Object>("get_Value").invoke();
            //     console.log(current);
            // }


            // inventoryEnum.class.methods.forEach(method => {
            //     console.log(method.name);
            // });
            // console.log(inventoryEnum);
        });

        Il2Cpp.trace(true)
            .classes(
                // PlayerClass,
                // // PlayerInventoriesModel,
                // BackpackInventoryController,
                Inventories
            )
            .filterMethods((method) => {
                if (method.name === "GetNowTs") return false;
                return method.name !== "get_TimeNow";
            })
            .and()
            .attach();

        // Il2Cpp.trace(true).methods().and().attach();

        // PlayerClass.methods.forEach(method => { console.log(method.name) });

    } catch (error) {
        console.error(error);
    }
});


recv("message", (message: any) => {
    if (message.type === "send") {
        // fs.appendFileSync(path.join(__dirname, "output.txt"), message.payload, 'utf8');
        console.error(message.payload);
        return;
    }
})