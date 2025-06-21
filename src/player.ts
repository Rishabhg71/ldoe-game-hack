

// Assets.Core.Models.Users.Player

import { CharacterModel } from "./character";

export class Player {
    private _player: Il2Cpp.Object;
    constructor() {
        this._player = this._getPlayerObject();
    }

    public get Character(): CharacterModel {
        const character: Il2Cpp.Object = this._player.method<Il2Cpp.Object>("get_Character").invoke();
        return new CharacterModel(character);
    }

    private _getGameManager(Client: Il2Cpp.Image): Il2Cpp.Object {
        const GameManagerClass = Client.class("Assets.Core.Manager.GameManager");
        const gameManagerArr = Il2Cpp.gc.choose(GameManagerClass)

        for (let index = 0; index < gameManagerArr.length; index++) {
            const element = gameManagerArr[index];
            return element;
        }
        throw Error("PlayerObject not found");
    }

    private _getPlayerObject(): Il2Cpp.Object {
        const Client = Il2Cpp.domain.assembly("Client").image;
        const gameManager = this._getGameManager(Client);

        return gameManager.method<Il2Cpp.Object>("get_Player").invoke();


        // const PlayerClass = Client.class("Assets.Core.Models.Users.Player");
        // const arr = Il2Cpp.gc.choose(PlayerClass)

        // console.log("[CLIENT]Number of instances of Assets.Core.Models.Users.Player ->", arr.length);
        // for (let index = 0; index < arr.length; index++) {
        //     const element = arr[index];
        //     return element;
        // }
        // throw Error("PlayerObject not found");
    }
}