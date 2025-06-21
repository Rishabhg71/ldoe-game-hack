import "frida-il2cpp-bridge";
import { Player } from "./player";
import { Controller } from "./controller";
import { Locations, moveToLocation } from "./locations";
import { Cell, Inventories } from "./inventory";

const CHEST_LOCATIONS = {
    CHEST_1: [-1.09, 0.21, 2.43],
    CHEST_2: [0.94, 0.21, 2.70],
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
async function main(tile_to_move: number) {
    return new Promise<void>((resolve, reject) => {
        try {
            Il2Cpp.perform(async () => {
                const player = new Player();
                let [x, y, z] = player.Character.position.toString().split(",").map((coord) => parseFloat(coord.trim().replace("(", "").replace(")", "")));
                const TILE_SIZE_STEP = 0.1;
                const TILE_SIZE_AMOUNT = 20;

                let i = 0;
                while (i < (TILE_SIZE_AMOUNT * tile_to_move)) {
                    z += TILE_SIZE_STEP;

                    await player.Character.teleport(x, y, z);
                    console.log("Player position:", [x, y, z]);
                    await wait(1000);
                    i++;
                }

                resolve();
            });
        } catch (error) {
            console.error("Error", error);
            reject();
        }
    });
}

async function movetile(tile_to_move: number, direction: "up" | "down" | "left" | "right") {
    return new Promise<void>((resolve, reject) => {
        try {
            Il2Cpp.perform(async () => {
                const player = new Player();
                let [x, y, z] = player.Character.position.toString().split(",").map((coord) => parseFloat(coord.trim().replace("(", "").replace(")", "")));
                // const TILE_SIZE_STEP = 0.1;
                // const TILE_SIZE_AMOUNT = 20;
                const TILE_SIZE_STEP = 0.2;
                const TILE_SIZE_AMOUNT = 10;

                let i = 0;
                while (i < (TILE_SIZE_AMOUNT * tile_to_move)) {
                    if (direction === "up") z += TILE_SIZE_STEP;
                    else if (direction === "down") z -= TILE_SIZE_STEP;
                    else if (direction === "left") x -= TILE_SIZE_STEP;
                    else if (direction === "right") x += TILE_SIZE_STEP;

                    // else throw new Error("Invalid direction. Use 'up', 'down', 'left', or 'right'.");
                    // z += TILE_SIZE_STEP;

                    await player.Character.teleport(x, y, z);
                    // console.log("Player position:", [x, y, z]);
                    await wait(1000);
                    i++;
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
    return new Promise<number>((resolve, reject) => {
        Il2Cpp.perform(async () => {
            try {
                const player = new Player();
                const health = player.Character.health;
                const Client = Il2Cpp.domain.assembly("Client").image;
                const Klass = Client.class("Assets.Core.Models.Builder.Workbench.FuelWorkbench")
                Il2Cpp.gc.choose(Klass).forEach((instance) => {
                    console.log("Instance of Workbench found:", instance);
                    const description = instance.field<Il2Cpp.Object>("_description").value
                    const fuelInventory = instance.method<Il2Cpp.Object>("get_FuelInventories").invoke();
                    new Inventories(fuelInventory).InventoryParts.forEach((inventory) => {
                        inventory.Cells.forEach((cell) => {
                            if (!cell.IsEmpty()) {
                                console.log(`Item in Workbench: ${cell.Stack.Id.toString().replace('"', "").replace('"', "")}, Amount: ${cell.Stack.GetAmount()}`);
                            }
                        });
                    })

                });

                // Klass.methods.forEach((method) => {
                //     console.log(`Method: ${method.name}, Return Type: ${method.returnType.name}`);
                // });

                // console.log(Il2Cpp.domain.assemblies.map((assembly) => assembly.name));

                // const mscorlib = Il2Cpp.domain.assembly("mscorlib").image;
                // const Klass2 = mscorlib.class("System.Collections.Generic.IEnumerable")



                // Uncomment the following lines to enable tracing and backtracing
                // Il2Cpp.backtrace(Backtracer.FUZZY).verbose(true).classes(Klass).and().attach();
                // Il2Cpp.trace().classes(Klass).and().attach();
                // .filterAssemblies((assembly) => assembly.name.includes("Client"))
                //     .filterClasses((klass) => klass.fullName.includes("Assets.Core.Game.Battle.Gui.InventoryUI.InventoryUiController"))
                //     .filterMethods((method) => true).and().attach();

                // console.log("Getting backpack items...", player.Character.inventories.Stacks.map((stack) => ({
                //     name: stack.Id,
                //     amount: stack.GetAmount()
                // })));
                resolve(health);
            } catch (error) {
                console.error("Error getting player health:", error);
                reject(error);
            }
        });
    });
}


async function move(location: "Trees_01_1" | "home") {
    return new Promise<void>((resolve, reject) => {
        Il2Cpp.perform(async () => {
            try {
                await Locations.moveToLocation(location);
                resolve();
            } catch (error) {
                console.error("Error moving player:", error);
                reject(error);
            }
        });
    });
}

async function enterCurrentLocation() {
    return new Promise<void>((resolve, reject) => {
        Il2Cpp.perform(async () => {
            try {
                await Locations.enterCurrentLocation();
                resolve();
            } catch (error) {
                console.error("Error moving player:", error);
                reject(error);
            }
        });
    });
}

function getPlayerHealth() {
    return new Promise<number>((resolve, reject) => {
        Il2Cpp.perform(async () => {
            try {
                const player = new Player();
                resolve(player.Character.health);
            } catch (error) {
                console.error("Error getting player health:", error);
                reject(error);
            }
        });
    });
}

function getBackpackItems() {
    return new Promise<any[]>((resolve, reject) => {
        Il2Cpp.perform(async () => {
            try {
                const player = new Player();
                const items = [];
                let x = 1;
                player.Character.inventories.InventoryParts.forEach((inventory) => {
                    inventory.Cells.forEach((cell) => {
                        if (!cell.IsEmpty()) {
                            items.push({
                                name: cell.Stack.Id.toString().replace('"', "").replace('"', ""),
                                amount: cell.Stack.GetAmount(),
                                cellIndex: x,
                            });
                        }
                        x++;
                    });
                });
                resolve(items);
            } catch (error) {
                console.error("Error getting backpack items:", error);
                reject(error);
            }
        });
    });
}

function trace() {

    Il2Cpp.perform(() => {
        // const Client = Il2Cpp.domain.assembly("Client").image;
        // const GlobalMapPointController = Client.class("Assets.Core.Game.Dialogs.Inventory.InventoryButtonsHandler");
        // const arr1 = Il2Cpp.gc.choose(GlobalMapPointController);
        // console.log("[CLIENT]Number Assets.Core.Game.Dialogs.Inventory.InventoryButtonsHandler ->", arr1.length);

        // for (let index = 0; index < arr1.length; index++) {
        //     const element = arr1[index];
        //     const inventory = element.field<Il2Cpp.Object>("_lootInventories").value;
        //     const items: any[] = [];
        //     new Inventories(inventory).InventoryParts.forEach((inventory) => {
        //         inventory.Cells.forEach((cell) => {
        //             if (!cell.IsEmpty()) {
        //                 console.log(cell.Stack.Id.toString());

        //                 items.push({
        //                     name: cell.Stack.Id.toString().replace('"', "").replace('"', ""),
        //                     amount: cell.Stack.GetAmount(),
        //                 });
        //             }
        //         });
        //     });
        //     console.log(items);
        // }

        Il2Cpp.trace(true).domain().filterClasses((klass) => {
            if (klass.fullName.includes("Assets.Core.Game.Dialogs.Inventory")) return true;
            // if (klass.fullName.includes("Assets.Core.Game.Dialogs.Inventory.InventoryButtonsHandler")) return true;

            return false;
        })
            .filterMethods((method) => {
                // if (method.name.includes("Add")) return true;
                // if (method.name.includes("Remove")) return true;
                if (method.name === "Exchange") return true;
                // if (method.name === "Remove") return true;
                // if (method.name === "InventoryButtonsHandler") return true;
                return false;
                return false;
            })
            .and().attach();
    })
}


function getChestItems() {
    return new Promise<void>((resolve, reject) => {
        return Il2Cpp.perform(() => {
            const Client = Il2Cpp.domain.assembly("Client").image;
            const GlobalMapPointController = Client.class("Assets.Core.Game.Dialogs.Inventory.InventoryButtonsHandler");
            const arr1 = Il2Cpp.gc.choose(GlobalMapPointController);
            console.log("[CLIENT]Number Assets.Core.Game.Dialogs.Inventory.InventoryButtonsHandler ->", arr1.length);

            for (let index = 0; index < arr1.length; index++) {
                const element = arr1[index];
                const inventory = element.field<Il2Cpp.Object>("_lootInventories").value;
                const items: any[] = [];
                new Inventories(inventory).InventoryParts.forEach((inventory) => {
                    inventory.Cells.forEach((cell) => {
                        if (!cell.IsEmpty()) {
                            items.push({
                                name: cell.Stack.Id.toString().replace('"', "").replace('"', ""),
                                amount: cell.Stack.GetAmount(),
                            });
                        }
                    });
                });
                resolve(items);
            }
        })
    })
}

function moveItemsFromPlayerToChest(item_name: string) {
    return new Promise<void>((resolve, reject) => {
        Il2Cpp.perform(async () => {
            function getChestEmptySlots() {
                return new Promise<{ cell: Cell; inventory: Inventories }[]>((resolve, reject) => {
                    Il2Cpp.perform(() => {
                        const Client = Il2Cpp.domain.assembly("Client").image;
                        const GlobalMapPointController = Client.class("Assets.Core.Game.Dialogs.Inventory.InventoryButtonsHandler");
                        const arr1 = Il2Cpp.gc.choose(GlobalMapPointController);
                        console.log("[CLIENT]Number Assets.Core.Game.Dialogs.Inventory.InventoryButtonsHandler ->", arr1.length);

                        for (let index = 0; index < arr1.length; index++) {
                            const element = arr1[index];
                            const inventory = element.field<Il2Cpp.Object>("_lootInventories").value;
                            const items: { cell: Cell; inventory: Inventories }[] = [];
                            new Inventories(inventory).InventoryParts.forEach((inventory) => {
                                inventory.Cells.forEach((cell) => {
                                    if (cell.IsEmpty()) {
                                        items.push({
                                            cell: cell,
                                            inventory: inventory
                                        });
                                    }
                                });
                            });
                            resolve(items);
                        }
                    })
                })
            }


            const emptyChestCells = await getChestEmptySlots();
            const player = new Player();
            const playerItems: { name: string; amount: number; cell: Cell; inventory: Inventories }[] = [];
            player.Character.inventories.InventoryParts.forEach((inventory) => {
                inventory.Cells.forEach((cell) => {
                    if (!cell.IsEmpty()) {
                        playerItems.push({
                            name: cell.Stack.Id.toString().replace('"', "").replace('"', ""),
                            amount: cell.Stack.GetAmount(),
                            cell: cell,
                            inventory: inventory
                        });
                        // inventory.
                        const cellToTransfer = emptyChestCells.shift();
                        console.log("Cell to transfer:", cellToTransfer);
                        if (cellToTransfer) {
                            inventory.ExchangeCell(cellToTransfer.cell, cell, inventory, cellToTransfer.inventory);
                        }
                    }
                });
            });
            resolve();
        });
    });
}

rpc.exports = {
    main: main,
    test: test,
    move: move,
    movetile: movetile,
    enterlocation: enterCurrentLocation,
    gethealth: getPlayerHealth,
    getbackpack: getBackpackItems,
    trace: trace,
    getchestitems: getChestItems,
    moveitemsfromplayertochest: moveItemsFromPlayerToChest,
}
