type LocationNames = "home" | "Trees_01_1";
const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

function getLocationDescriptionFor(place: LocationNames) {
    const Client = Il2Cpp.domain.assembly("Client").image;
    const GlobalMapPointController = Client.class("Assets.Core.Game.GlobalMap.GlobalMapPointController");
    const arr1 = Il2Cpp.gc.choose(GlobalMapPointController);
    console.log("[CLIENT]Number Assets.Core.Game.GlobalMap.GlobalMapPointController ->", arr1.length);

    for (let index = 0; index < arr1.length; index++) {
        const element = arr1[index];
        const name = element.field<Il2Cpp.Object>("_locationViewDescription").value.method("get_Id").invoke();
        // if (String(name).replaceAll('"', "") === "Trees_01_1") {
        if (String(name).replace('"', "").replace('"', "") === place) {
            return element.field<Il2Cpp.Object>("_locationDescription").value;
        }
    }
    throw Error("Location you tried to select is not found");
}

function getMap() {
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


export class Locations {
    private constructor() { }

    public static async moveToLocation(name: LocationNames) {
        const Client = Il2Cpp.domain.assembly("Client").image;

        const map = getMap();
        const location = getLocationDescriptionFor(name);
        map.method<Il2Cpp.Object>("MoveToPoint").invoke(location);
    }

    public static async enterCurrentLocation() {
        const Client = Il2Cpp.domain.assembly("Client").image;

        const GlobalMapPlayerModelView = Client.class("Assets.Core.Game.GlobalMap.GlobalMapPlayerModelView");
        const arr = Il2Cpp.gc.choose(GlobalMapPlayerModelView);
        console.log("[CLIENT]Number Assets.Core.Game.GlobalMap.Models.GlobalMapLocationDescription ->", arr.length);
        for (let index = 0; index < arr.length; index++) {
            const element = arr[index];
            element.method<void>("EnterLocation").invoke();
        }

    }
}
