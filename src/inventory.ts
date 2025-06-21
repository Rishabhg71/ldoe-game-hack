

import { CharacterModel } from "./character";

function enumerateToArray<T extends number | Il2Cpp.Object | Il2Cpp.String>(list: Il2Cpp.Object): Array<T> {
    const res: Array<T> = [];
    const enumerator = list.method<Il2Cpp.Object>("GetEnumerator").invoke();
    while (enumerator.method<boolean>("MoveNext").invoke()) {
        res.push(enumerator.method<T>("get_Current").invoke());
    }
    return res;
}

// Assets.Core.Models.InventoryModels.Inventories
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

    public ExchangeCell(from: Cell, to: Cell, fromInventory: Inventories, toInventory: Inventories): void {
        this._ref.method("ExchangeCell").invoke(from._ref, to._ref, fromInventory._ref, toInventory._ref);
    }
}

// Assets.Core.Models.InventoryModels.InventoryCell
export class Cell {
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
    public get Stack(): Stack {
        // return this._ref.method<Il2Cpp.Object>("get_Stack").invoke()
        return new Stack(this._ref.method<Il2Cpp.Object>("get_Stack").invoke())
    }
    public get Id(): Il2Cpp.String {
        return this._ref.method<Il2Cpp.String>("get_Id").invoke()
    }
}


// Assets.Core.Models.InventoryModels.InventoryStack
class Stack {
    _ref: Il2Cpp.Object;
    constructor(stack: Il2Cpp.Object) {
        this._ref = stack;
    }
    public GetAmount(): number {
        return this._ref.method<number>("GetAmount").invoke()
    }
    public get Id(): Il2Cpp.String {
        return this._ref.method<Il2Cpp.String>("get_Id").invoke()
    }
}
