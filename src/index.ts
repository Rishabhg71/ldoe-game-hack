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
        const Inventories = Client.class("Assets.Core.Models.InventoryModels.Inventories");
        const HealthController = Client.class("Assets.Core.Game.Battle.Gui.MainUI.HealthBar.HealthController");

        waitForPlayer().then((player) => {
            console.log("Got the player object");
            const Character = player.method<Il2Cpp.Object>("get_Character").invoke();

            const Inventories = Character.method<Il2Cpp.Object>("get_Inventories").invoke()
            console.log("MY backpack limit", Inventories.method<number>("CellsCount").invoke());

            setInterval(() => {
                const Health = Character.tryField<Il2Cpp.Object>("_health")
                if (Health && Health?.value.method<number>("GetAmount").invoke() < 40) {

                    Character.method("Heal").invoke(100);
                }
                console.log("My health", Health?.value.method("GetAmount").invoke());
            }, 1000);
        });

        Il2Cpp.trace(true)
            .classes(
            )
            .filterMethods((method) => {
                if (method.name === "GetNowTs") return false;
                return method.name !== "get_TimeNow";
            })
            .and()
            .attach();

    } catch (error) {
        send(error);
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