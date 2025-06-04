
// Assets.Core.Models.InventoryModels.Inventories

import { CharacterModel } from "./character";

function enumerateToArray<T extends number | Il2Cpp.Object | Il2Cpp.String>(list: Il2Cpp.Object): Array<T> {
    const res: Array<T> = [];
    const enumerator = list.method<Il2Cpp.Object>("GetEnumerator").invoke();
    while (enumerator.method<boolean>("MoveNext").invoke()) {
        res.push(enumerator.method<T>("get_Current").invoke());
    }
    return res;
}

export class Inventories {
    // private _character: CharacterModel;
    private _ref: Il2Cpp.Object;

    constructor(inventory: Il2Cpp.Object) {
        this._ref = inventory;
    }

    public CellCount(): number {
        return this._ref.method<number>("CellsCount").invoke()
    }

    public get InventoryParts(): Array<Inventories> {
        const inventoryParts = this._ref.method<Il2Cpp.Object>("get_InventoryParts").invoke()

        return enumerateToArray<Il2Cpp.Object>(inventoryParts).map((inventoryPart) => {
            return new Inventories(inventoryPart)
        })
    }

    public get Cells(): Array<Cell> {
        const cells = this._ref.method<Il2Cpp.Object>("get_Cells").invoke()
        return enumerateToArray<Il2Cpp.Object>(cells).map((cell) => {
            return new Cell(cell)
        })
    }
}

// Assets.Core.Models.InventoryModels.InventoryCell
class Cell {
    _ref: Il2Cpp.Object;
    constructor(cell: Il2Cpp.Object) {
        this._ref = cell;
    }
    public IsEmpty(): boolean {
        return this._ref.method<boolean>("IsEmpty").invoke()
    }
    public get CellIndex(): number {
        return this._ref.method<number>("get_CellIndex").invoke()
    }
    public get Stack(): Il2Cpp.Object {
        return this._ref.method<Il2Cpp.Object>("get_Stack").invoke()
    }
    public get Id(): Il2Cpp.String {
        return this._ref.method<Il2Cpp.String>("get_Id").invoke()
    }
}
