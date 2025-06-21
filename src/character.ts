// Assets.Core.Models.Characters.CharacterModel

import BaseWrapper from "./base";
import { Inventories } from "./inventory";

export class CharacterModel extends BaseWrapper {
    public _ref: Il2Cpp.Object;
    constructor(character: Il2Cpp.Object) {
        super();
        this._ref = character;

    }

    public get health(): number {
        const Health = this._ref.field<Il2Cpp.Object>("_health")?.value
        return Health.method<number>("GetAmount").invoke();
    }
    public heal(amount: number): void {
        this._ref.method<void>("Heal").invoke(amount);
    }
    public get position(): Il2Cpp.Object {
        return this._ref.method<Il2Cpp.Object>("get_Position").invoke();
    }

    public async teleport(x: number, y: number, z: number) {
        x = Math.trunc(x * 100) / 100;
        y = Math.trunc(y * 100) / 100;
        z = Math.trunc(z * 100) / 100;

        const playerPositionVector3 = this._ref.method<Il2Cpp.Object>("get_Position").invoke();
        playerPositionVector3.field<number>("x").value = x;
        playerPositionVector3.field<number>("y").value = y;
        playerPositionVector3.field<number>("z").value = z;

        this._ref.method<void>("SetPosition").invoke(playerPositionVector3, true, false, true);

    }

    public get inventories(): Inventories {
        const inv = this._ref.method<Il2Cpp.Object>("get_Inventories").invoke()
        return new Inventories(inv)
    }

}