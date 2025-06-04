export class Controller {
    GameManager: Il2Cpp.Object;
    MainUiController: Il2Cpp.Object;
    DialogsController: Il2Cpp.Object;

    constructor() {
        this.MainUiController = this.getMainUiController()
        this.GameManager = this.getGameManager()

        // this.DialogsController = this.GameManager.field<Il2Cpp.Object>("DialogsManager").value.field<Il2Cpp.Object>("DialogsController").value.method<Il2Cpp.Object>("get_CurrentDialog").invoke();
        // this.DialogsController = this.getDialogsController();
    }

    private getMainUiController() {
        const Client = Il2Cpp.domain.assembly("Client").image;
        const Klass = Client.class("Assets.Core.Game.Battle.Gui.MainUI.MainUiController")
        const arr = Il2Cpp.gc.choose(Klass)

        console.log("Number of MainUiController should be 1???", arr.length);

        for (let index = 0; index < arr.length; index++) {
            const element = arr[index];
            if (element.field("Container").value !== null) {
                return element.field<Il2Cpp.Object>("Container").value;
            }
        }

        throw new Error("MainUiController not found");
    }
    private getGameManager() {
        const Client = Il2Cpp.domain.assembly("Client").image;
        const Klass = Client.class("Assets.Core.Manager.GameManager")
        const arr = Il2Cpp.gc.choose(Klass)

        console.log("Number of GameManager should be 1???", arr.length);

        for (let index = 0; index < arr.length; index++) {
            const element = arr[index];
            return element;
        }

        throw new Error("GameManager not found");
    }

    wrapper(callback: () => Promise<any>) {
        return new Promise(async (resolve, reject) => {
            try {
                await callback();

            } catch (error) {
                console.error("Error", error);
            }
            resolve(true);
        });
    }


    pressAuto() {
        return this.wrapper(async () => {
            const Client = Il2Cpp.domain.assembly("Client").image;
            const Klass = Client.class("Assets.Core.Game.Battle.Gui.MainUI.Buttons.AutoUseController")
            const arr = Il2Cpp.gc.choose(Klass)

            arr[0].method("OnDown").invoke(Il2Cpp.string(""));
        });
    }

    pressAttack() {
        return this.wrapper(async () => {
            const Client = Il2Cpp.domain.assembly("Client").image;
            const Klass = Client.class("Assets.Core.Game.Battle.Gui.MainUI.Buttons.AttackController")
            const arr = Il2Cpp.gc.choose(Klass)

            arr[0].method("OnDown").invoke(Il2Cpp.string(""));
        });
    }

    pressUse() {
        return this.wrapper(async () => {
            // const Client = Il2Cpp.domain.assembly("Client").image;
            // const Klass = Client.class("Assets.Core.Game.Battle.Gui.MainUI.Buttons.UseController")
            // const arr = Il2Cpp.gc.choose(Klass)

            // arr[0].method("OnDown").invoke(Il2Cpp.string(""));
            // this.GameManager.field<Il2Cpp.Object>("UseController").value.method("OnDown").invoke(Il2Cpp.string(""))
            this.MainUiController.field<Il2Cpp.Object>("UseController").value.method("OnDown").invoke(Il2Cpp.string(""))
        });
    }

    pressClosePanel() {
        return this.wrapper(async () => {
            const Client = Il2Cpp.domain.assembly("Client").image;
            const Klass = Client.class("Assets.Core.Game.Dialogs.Inventory.LootDialog")
            const arr = Il2Cpp.gc.choose(Klass)
            console.log("Number of LootDialog =", arr.length);

            for (let index = 0; index < arr.length; index++) {
                const element = arr[index];
                if (element.method("CloseDialog") === null) {
                    continue;
                }

                element.method("CloseDialog").invoke();
                console.log("Closing panel");
            }
            // this.GameManager.field<Il2Cpp.Object>("UseController").value.method("OnDown").invoke(Il2Cpp.string(""))

            // this.DialogsController = this.GameManager.field<Il2Cpp.Object>("DialogsManager").value.field<Il2Cpp.Object>("DialogsController").value
            // // .method<Il2Cpp.Object>("get_CurrentDialog")
            // // .invoke();
            // console.log(this.DialogsController);

            // this.DialogsController.method("HideDialog").invoke();
        });
    }
}