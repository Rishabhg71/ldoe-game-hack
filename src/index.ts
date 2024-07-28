import "frida-il2cpp-bridge";
import * as fs from "fs";
import * as path from "path";
console.log("Frida Loaded Successfully");

const TIMEOUT = 30000; // 30 seconds

type DpadDirection = "w" | "a" | "s" | "d" | "wa" | "wd" | "sa" | "sd" | "stop";

class ObjectGetters {
    // @ts-ignore
    public player: Il2Cpp.Object;
    // @ts-ignore
    public ui: Il2Cpp.Object;

    public async doInitialSetup() {
        this.player = await this.waitForPlayer();
        this.ui = await this.waitForUi();
    }
    public getDpad() {
        const dpad = this.ui.tryField<Il2Cpp.Object>("DpadController")?.value;
        if (!dpad) throw Error("dpad is null");

        return dpad;
    }

    public async waitForPlayer(): Promise<
        Il2Cpp.Object
    > {
        const Client = Il2Cpp.domain.assembly("Client").image;

        const PlayerClass = Client.class("Assets.Core.Models.Users.Player");

        let PlayerObject: Il2Cpp.Object | null = null;
        PlayerClass.method("get_TimeNow").implementation = function () {
            // @ts-ignore
            if (!PlayerObject) PlayerObject = this;
            return this.method("get_TimeNow").invoke();
        };

        return new Promise((resolve, reject) => {
            const interval = setInterval(() => {
                if (PlayerObject) {
                    resolve(PlayerObject);
                    interval && clearInterval(interval);
                } else console.log("Waiting for PlayerObject");
            }, 2000);
        });
    }

    public async waitForUi(): Promise<Il2Cpp.Object> {
        const Client = Il2Cpp.domain.assembly("Client").image;

        const BattleUiController = Client.class(
            "Assets.Core.Game.Battle.BattleUiController"
        );

        // BattleUiController.fields.forEach((field) => { console.log(field.name) });

        let battleUiController: Il2Cpp.Class | Il2Cpp.ValueType | Il2Cpp.Object | null = null;

        BattleUiController.method("Update").implementation = function () {
            if (!battleUiController) battleUiController = this;
            return this.method("Update").invoke();
        };

        return new Promise((resolve, reject) => {
            const interval = setInterval(() => {
                let str = "Assets.Core.Game.Battle.BattleUiController -> ";

                if (!battleUiController) return console.log(str + "null");
                const battleContainer =
                    battleUiController.tryField<Il2Cpp.Object>("Container")?.value;
                str += "Assets.Core.Game.Battle.BattleUiContainer -> ";

                if (!battleContainer) return console.log(str + "null");
                const mainUiController =
                    battleContainer?.tryField<Il2Cpp.Object>("MainUiController")?.value;
                str += "Assets.Core.Game.Battle.Gui.MainUI.MainUiController -> ";

                if (!mainUiController) return console.log(str + "null");
                const mainUiContainer =
                    mainUiController.tryField<Il2Cpp.Object>("Container")?.value;

                if (!mainUiContainer) return console.log(str + "null");
                str += "Assets.Core.Game.Battle.Gui.MainUI.MainUiContainer";
                console.log(str);

                resolve(mainUiContainer);
                clearInterval(interval);
            }, 2000);
        });
    }
}


class Character {
    characterRef: Il2Cpp.Object;
    object_getter: ObjectGetters;

    constructor(character: Il2Cpp.Object, object_getter: ObjectGetters) {
        this.characterRef = character;
        this.object_getter = object_getter;
    }
    public getHealth() {
        const Health = this.characterRef.tryField<Il2Cpp.Object>("_health")?.value
        if (!Health) throw Error("Health is null");
        return Health.method<number>("GetAmount").invoke();
    }

    public getInventorySpace() {
        const Inventories = this.characterRef.method<Il2Cpp.Object>("get_Inventories").invoke();
        return Inventories.method<number>("CellsCount").invoke()
    }
    public heal() {
        this.characterRef.method<void>("Heal").invoke(90);
    }

    public async runFor(direction: DpadDirection, time: number) {
        this.run(direction);
        await new Promise((resolve) => setTimeout(resolve, time));
        console.log("Stopping Player");
        const dpad = this.object_getter.getDpad()
        dpad.method<void>("StopDpad").invoke();
        // this.run("stop");
    }

    public run(direction: DpadDirection) {
        const dpad = this.object_getter.getDpad()

        const UnityEngine = Il2Cpp.domain.assembly("UnityEngine").image;

        let Vector2 = UnityEngine.class("UnityEngine.Vector2").new();
        Vector2.method<void>("Set").invoke(0.5, 0.5);
        Vector2 = Vector2.method<Il2Cpp.Object>("get_normalized").invoke()

        let cords = [0.0, 0.0];
        if (direction === "w") cords = [0.0, 1.0];
        if (direction === "a") cords = [-1.0, 0.0];
        if (direction === "s") cords = [0.0, -1.0];
        if (direction === "d") cords = [1.0, 0.0];
        if (direction === "wa") cords = [-1.0, 1.0];
        if (direction === "wd") cords = [1.0, 1.0];
        if (direction === "sa") cords = [-1.0, -1.0];
        if (direction === "sd") cords = [1.0, -1.0];
        if (direction === "stop") cords = [0, 0];

        Vector2.method<void>("Set").invoke(cords[0], cords[1]);
        dpad.method<void>("Run").invoke(Vector2, 0.9);
    }
}

class GamePlayer {
    object_getters: ObjectGetters;
    character: Character;

    constructor(object_getters: ObjectGetters) {
        this.object_getters = object_getters;

        const characterRef = this.object_getters.player.method<Il2Cpp.Object>("get_Character").invoke();
        const character = new Character(characterRef, object_getters)
        this.character = character;
    }

    public async start() {
        // this.character.run("wa");
        this.character.runFor("wa", 2000);

        // setInterval(() => {
        //     const health = this.character.getHealth();
        //     if (health < 40) {
        //         // this.character.heal();
        //     }
        //     console.log("My health", this.character.getHealth());
        // }, 1000);

    }
}

Il2Cpp.perform(async () => {
    console.log(
        "libil2cpp.so loaded, performing Il2Cpp operations...",
        Il2Cpp.unityVersion
    );
    try {
        const Client = Il2Cpp.domain.assembly("Client").image;

        const class_getters = new ObjectGetters();
        await class_getters.doInitialSetup();

        const game = new GamePlayer(class_getters);
        await game.start();

        // Il2Cpp.trace(true).domain().filterClasses((klass) => {
        //     if (`${klass.namespace}.${klass.name}`.includes("Assets.Core.Game.Battle.Gui.MainUI")) return true;
        //     return false;
        // }).and().attach();

        Il2Cpp.trace(true)
            .classes()
            .filterMethods((method) => {
                if (method.name === "GetNowTs") return false;
                if (method.name === "get_TimeNow") return false;

                return true;
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
});
