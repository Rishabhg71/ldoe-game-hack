type DpadDirection = "w" | "a" | "s" | "d" | "wa" | "wd" | "sa" | "sd" | "stop";
type ControlEvents = "attack" | "auto" | "use" | "take_all" | "put_all" | "close_inventory" | "run" | "craft_button" | "craft_item" | "dbl_click_inventory";
type LocationNames = "home" | "Trees_01_1";
type BackpackItems = {
    [key: string]: { amount: number, object: Il2Cpp.Object[] },
};
type BackpackItemsWithIndex = {
    [key: number]: { amount: number, object: Il2Cpp.Object, itemName: string },
};

export { DpadDirection, ControlEvents, LocationNames, BackpackItems, BackpackItemsWithIndex };