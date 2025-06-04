import "frida-il2cpp-bridge";
import { Player } from "./player";
import { Controller } from "./controller";


const CHEST_LOCATIONS = {
    CHEST_1: [12.23, 0.21, -3.02],
    CHEST_2: [12.33, 0.21, -5.05],
    CHEST_3: [12.43, 0.21, -7.05],
    CHEST_4: [12.47, 0.21, -9.17],
    CHEST_5: [12.24, 0.21, -11.16],
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

type ChestKeys = keyof typeof CHEST_LOCATIONS;

const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
async function main() {
    return new Promise<void>((resolve, reject) => {
        try {
            Il2Cpp.perform(async () => {
                Process.setExceptionHandler((details) => {
                    console.log('[!] Exception detected:');
                    console.log('Address:', details.address);
                    console.log('Type:', details.type);
                    console.log('Stack:', Thread.backtrace(details.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress).join('\n'));

                    return false;
                });
                console.log("Il2Cpp loaded");

                const controller = new Controller();

                const keys = Object.keys(CHEST_LOCATIONS)
                for (let index = 0; index < keys.length; index++) {
                    const player = new Player();
                    const key = keys[index];
                    const location = CHEST_LOCATIONS[key as ChestKeys];
                    player.Character.teleport(location[0], location[1], location[2]);
                    await wait(5000);
                    await controller.pressUse();
                    await wait(5000);
                    await controller.pressClosePanel();
                    await wait(5000);
                }

                resolve();
            });
        } catch (error) {
            console.error("Error", error);
            reject();
        }
    });
}


async function test() {
    return new Promise<void>((resolve, _reject) => {
        Il2Cpp.perform(async () => {
            try {


                // const Client = Il2Cpp.domain.assembly("Client").image;
                // const Klass = Client.class("Assets.Core.Game.Battle.Gui.InventoryUI.InventoryUiController")
                // Il2Cpp.backtrace(Backtracer.FUZZY).verbose(true).classes(Klass).and().attach();
                // Il2Cpp.trace().classes(Klass).and().attach();
                // .filterAssemblies((assembly) => assembly.name.includes("Client"))
                // .filterClasses((klass) => klass.fullName.includes("Assets.Core.Game.Battle.Gui.InventoryUI.InventoryUiController"))
                // .filterMethods((method) => true).and().attach();

                console.log("Il2Cpp loaded");
            } catch (error) {
                console.error("Error", error);
            }

            resolve();
        });
    });
}

rpc.exports = {
    main: main,
    test: test,
}
