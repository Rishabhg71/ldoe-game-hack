for new devices
$ adb root # might be required
$ adb push frida-server /data/local/tmp/
$ adb shell "chmod 755 /data/local/tmp/frida-server"

adb connect 127.0.0.1:62001 Nox

adb shell am set-debug-app -w zombie.survival.craft.z
adb shell am clear-debug-app

adb shell "/data/local/tmp/frida-server &"



adb shell cat /proc/<pid>/maps | grep libil2cpp.so
adb shell ps | grep com.android.chrome

adb shell getprop ro.product.cpu.abi




MyOwnInventory: Assets.Core.Models.Users.Player.get_Character -> CharacterModel.get_Inventories()

# Locations
Stones_01_5
Trees_01_1
Port
FishingPier
Tower_town
Motel
Farm_01
Stones_02_79
Shelter_01_60
Tower_01_16
Trees_02_13
Boss_12
Shelter_01_8
Stones_01_7
Stones_01_6
Trees_01_3
Trees_01_2
home
Found Location
Trees_02_14
Trees_02_15
Trees_02_Locked_01
Tower_02_17
Shelter_02_19
Oil_Plant_20
Police_Station_01
New_Gas_Station_01
Swamp_01_2
Swamp_01_1
Quarry
TowerIsland
CaveIsland
OilPlatform
NewBase
TransportHub







il2cpp:
0x017b408c ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::OnPointerClick(this = Cell (14) (Assets.Core.Game.Dialogs.Inventory.InventoryCellController), eventData = <b>Position</b>: (662.59, 454.50))
0x017b8218 │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::OnPointerClick(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController, eventData)
0x017b1184 │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.CellProxyPointerEventsHandlerBase::HandleDoubleClick(this = Assets.Core.Game.Dialogs.Inventory.CellProxyPointerEventsHandlerMobile)
0x017b3654 │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::SetSelect(this = Cell (14) (Assets.Core.Game.Dialogs.Inventory.InventoryCellController), state = false)
0x017b7098 │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::SetSelect(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController, state = false)
0x017b5cf8 │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::ResetBackground(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b5cf8 │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::ResetBackground
0x017b7098 │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::SetSelect
0x017b3654 │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::SetSelect
0x017939f8 │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_Inventories(this = Cell (14) (Assets.Core.Game.Dialogs.Inventory.InventoryCellController))
0x017b4844 │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_Inventories(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b4844 │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_Inventories = Assets.Core.Models.InventoryModels.Inventories
0x017939f8 │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_Inventories = Assets.Core.Models.InventoryModels.Inventories
0x025266b8 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x025266b8 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell::Check = true
0x02524974 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::get_Description(this = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell)
0x02524974 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::get_Description = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCellDescription
0x01793ab0 │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_InventoryIndex(this = Cell (14) (Assets.Core.Game.Dialogs.Inventory.InventoryCellController))
0x017b4834 │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_InventoryIndex(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b4834 │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_InventoryIndex = 1
0x01793ab0 │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_InventoryIndex = 1
0x01793b68 │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_InventoryCell(this = Cell (14) (Assets.Core.Game.Dialogs.Inventory.InventoryCellController))
0x017b483c │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_InventoryCellIndex(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b483c │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_InventoryCellIndex = 4
0x01793b68 │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_InventoryCell = 4
0x02526bdc │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::CheckRemove(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, other = null)
0x02526bdc │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::CheckRemove = true
0x025266b8 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x025266b8 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell::Check = true
0x02522e44 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::Add(this = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02524ddc │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::StackAttach(this = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell)
0x02524ddc │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::StackAttach
0x02525268 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CallStackAdded(this = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x017b5f68 │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::InventoryCellOnStackAdded(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController, cell = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x017b5fb0 │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::UpdateStackController(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x018262e8 │ │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCell.StackTagsViewController::OnInit(this = Assets.Core.Game.Dialogs.Inventory.InventoryCell.StackTagsViewController)
0x018262e8 │ │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCell.StackTagsViewController::OnInit
0x02524998 │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::get_Entity(this = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell)
0x02524998 │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::get_Entity = null
0x017b7144 │ │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::SetEnabled(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController, state = true)
0x0182693c │ │ │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCell.StackTagsViewController::SetEnabled(this = Assets.Core.Game.Dialogs.Inventory.InventoryCell.StackTagsViewController, state = true)
0x0182693c │ │ │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCell.StackTagsViewController::SetEnabled
0x017b6d28 │ │ │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::UpdateCellDefault(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController, cellEnabled = true)
0x017b6d28 │ │ │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::UpdateCellDefault
0x017b7144 │ │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::SetEnabled
0x017b5fb0 │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::UpdateStackController
0x017b68d0 │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::UpdateElementalController(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b6abc │ │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::BuildElementalCellController(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b6abc │ │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::BuildElementalCellController = Assets.Core.Game.Dialogs.Inventory.StackControllers.EmptyCellElementalModifierController
0x017b68d0 │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::UpdateElementalController
0x017b34c4 │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::OnProxyChanged(this = MaterialCell (Assets.Core.Game.Dialogs.Inventory.InventoryCellController))
0x017981b8 │ │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::SetActive(this = MaterialCell (Assets.Core.Game.Dialogs.Inventory.InventoryCellController), state = true)
0x017b72b0 │ │ │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::SetActive(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController, state = true)
0x0252564c │ │ │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x017b5cf8 │ │ │ │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::ResetBackground(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b5cf8 │ │ │ │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::ResetBackground
0x01868614 │ │ │ │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.Containers.InventoryCellContainer::SetIconAlphaState(this = MaterialCell (Assets.Core.Game.Dialogs.Inventory.Containers.InventoryCellContainer), isTransparent = false)
0x01868614 │ │ │ │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.Containers.InventoryCellContainer::SetIconAlphaState
0x017b754c │ │ │ │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::SetRaycastActive(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController, state = true)
0x017b754c │ │ │ │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::SetRaycastActive
0x017b72b0 │ │ │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::SetActive
0x017981b8 │ │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::SetActive
0x017b34c4 │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::OnProxyChanged
0x017b5f68 │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::InventoryCellOnStackAdded
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02525268 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CallStackAdded
0x02524fa4 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::ClearEmptyStack(this = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell)
0x02524fa4 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::ClearEmptyStack
0x02522e44 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::Add
0x02526b30 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x02526b30 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true
0x01793ab0 │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_InventoryIndex(this = Cell (14) (Assets.Core.Game.Dialogs.Inventory.InventoryCellController))
0x017b4834 │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_InventoryIndex(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b4834 │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_InventoryIndex = 1
0x01793ab0 │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_InventoryIndex = 1
0x01793b68 │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_InventoryCell(this = Cell (14) (Assets.Core.Game.Dialogs.Inventory.InventoryCellController))
0x017b483c │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_InventoryCellIndex(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b483c │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_InventoryCellIndex = 4
0x01793b68 │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_InventoryCell = 4
0x02523188 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::Clear(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell)
0x025252b8 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::StackDetach(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell)
0x025252b8 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::StackDetach
0x025254b0 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CallStackRemoved(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x017b5f08 │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::InventoryCellOnStackRemoved(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController, cell = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x017b5fb0 │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::UpdateStackController(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x02524998 │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::get_Entity(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell)
0x02524998 │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::get_Entity = Assets.Core.Models.Characters.CharacterModel
0x01826d88 │ │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCell.StackTagsViewController::OnDispose(this = Assets.Core.Game.Dialogs.Inventory.InventoryCell.StackTagsViewController)
0x01868470 │ │ │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.Containers.InventoryCellContainer::ClearSlots(this = Cell (14) (Assets.Core.Game.Dialogs.Inventory.Containers.InventoryCellContainer))
0x01868470 │ │ │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.Containers.InventoryCellContainer::ClearSlots
0x01826d88 │ │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCell.StackTagsViewController::OnDispose
0x017b5cf8 │ │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::ResetBackground(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b5cf8 │ │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::ResetBackground
0x017b6d28 │ │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::UpdateCellDefault(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController, cellEnabled = false)
0x017b6d28 │ │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::UpdateCellDefault
0x017b5fb0 │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::UpdateStackController
0x017b68d0 │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::UpdateElementalController(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b6abc │ │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::BuildElementalCellController(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b6abc │ │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::BuildElementalCellController = Assets.Core.Game.Dialogs.Inventory.StackControllers.EmptyCellElementalModifierController
0x017b68d0 │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::UpdateElementalController
0x017b34c4 │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::OnProxyChanged(this = Cell (14) (Assets.Core.Game.Dialogs.Inventory.InventoryCellController))
0x017981b8 │ │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::SetActive(this = Cell (14) (Assets.Core.Game.Dialogs.Inventory.InventoryCellController), state = true)
0x017b72b0 │ │ │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::SetActive(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController, state = true)
0x0252564c │ │ │ │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ │ │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x017b5cf8 │ │ │ │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::ResetBackground(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b5cf8 │ │ │ │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::ResetBackground
0x01868614 │ │ │ │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.Containers.InventoryCellContainer::SetIconAlphaState(this = Cell (14) (Assets.Core.Game.Dialogs.Inventory.Containers.InventoryCellContainer),
 isTransparent = true)
0x01868614 │ │ │ │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.Containers.InventoryCellContainer::SetIconAlphaState
0x017b754c │ │ │ │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::SetRaycastActive(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController, state = true)
0x017b754c │ │ │ │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::SetRaycastActive
0x017b72b0 │ │ │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::SetActive
0x017981b8 │ │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::SetActive
0x017b34c4 │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::OnProxyChanged
0x017b5f08 │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::InventoryCellOnStackRemoved
0x025254b0 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CallStackRemoved
0x02523188 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::Clear
0x017b1184 │ │ │ └─Assets.Core.Game.Dialogs.Inventory.CellProxyPointerEventsHandlerBase::HandleDoubleClick
0x017b132c │ │ └─Assets.Core.Game.Dialogs.Inventory.CellProxyPointerEventsHandlerMobile::OnPointerClick
0x017b8218 │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::OnPointerClick
0x017b408c └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::OnPointerClick

il2cpp:
0x02526b30 ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525724 │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, args = Assets.Core.Models.Arguments.Arguments)
0x0252564c │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckActive = true
0x02525724 │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CheckPlaceStack = true
0x02526b30 └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::Check = true

il2cpp:
0x02525500 ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::OnStackAmountChanged(this = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack, oldamount = 3, newamount = 2)
0x02524fa4 │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::ClearEmptyStack(this = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell)
0x02524fa4 │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::ClearEmptyStack
0x02525500 └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::OnStackAmountChanged

il2cpp:
0x02523e10 ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::OnStackChanged(this = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02523e10 └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::OnStackChanged

il2cpp:
0x02525500 ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::OnStackAmountChanged(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack, oldamount = 2, newamount = 3)
0x02524fa4 │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::ClearEmptyStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell)
0x02524fa4 │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::ClearEmptyStack
0x02525500 └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::OnStackAmountChanged

il2cpp:
0x02523e10 ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::OnStackChanged(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02523e10 └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::OnStackChanged









































































   . . . .   Connected to SM G988N (id=127.0.0.1:62001)
[SM G988N::zombie.survival.craft.z ]-> il2cpp:
0x017b0cec ┌─Assets.Core.Game.Dialogs.Inventory.CellProxyPointerEventsHandlerBase::ShowTooltip(this = Assets.Core.Game.Dialogs.Inventory.CellProxyPointerEventsHandlerMobile, immediate = false)
0x017b0cec └─Assets.Core.Game.Dialogs.Inventory.CellProxyPointerEventsHandlerBase::ShowTooltip

il2cpp:
0x017b0c38 ┌─Assets.Core.Game.Dialogs.Inventory.CellProxyPointerEventsHandlerBase::HideTooltip(this = Assets.Core.Game.Dialogs.Inventory.CellProxyPointerEventsHandlerMobile)
0x017b0c38 └─Assets.Core.Game.Dialogs.Inventory.CellProxyPointerEventsHandlerBase::HideTooltip

il2cpp:
0x017b0efc ┌─Assets.Core.Game.Dialogs.Inventory.CellProxyPointerEventsHandlerBase::HandleCellSelection(this = Assets.Core.Game.Dialogs.Inventory.CellProxyPointerEventsHandlerMobile)
0x017b3654 │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::SetSelect(this = MaterialCell (Assets.Core.Game.Dialogs.Inventory.InventoryCellController), state = true)
0x017b7098 │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::SetSelect(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController, state = true)
0x017b7098 │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::SetSelect
0x017b3654 │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::SetSelect
0x02526c40 │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell::CheckRemove(this = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell, other = null)
0x02526c40 │ └─Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell::CheckRemove = true
0x017939f8 │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_Inventories(this = MaterialCell (Assets.Core.Game.Dialogs.Inventory.InventoryCellController))
0x017b4844 │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_Inventories(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b4844 │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_Inventories = Assets.Core.Models.InventoryModels.Inventories
0x017939f8 │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_Inventories = Assets.Core.Models.InventoryModels.Inventories
0x01793ab0 │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_InventoryIndex(this = MaterialCell (Assets.Core.Game.Dialogs.Inventory.InventoryCellController))
0x017b4834 │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_InventoryIndex(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b4834 │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_InventoryIndex = 0
0x01793ab0 │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_InventoryIndex = 0
0x01793b68 │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_InventoryCell(this = MaterialCell (Assets.Core.Game.Dialogs.Inventory.InventoryCellController))
0x017b483c │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_InventoryCellIndex(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b483c │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_InventoryCellIndex = 0
0x01793b68 │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_InventoryCell = 0
0x02524974 │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::get_Description(this = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell)
0x02524974 │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::get_Description = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCellDescription
0x017b0efc └─Assets.Core.Game.Dialogs.Inventory.CellProxyPointerEventsHandlerBase::HandleCellSelection

il2cpp:
0x017b1184 ┌─Assets.Core.Game.Dialogs.Inventory.CellProxyPointerEventsHandlerBase::HandleDoubleClick(this = Assets.Core.Game.Dialogs.Inventory.CellProxyPointerEventsHandlerMobile)
0x017b3654 │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::SetSelect(this = MaterialCell (Assets.Core.Game.Dialogs.Inventory.InventoryCellController), state = false)
0x017b7098 │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::SetSelect(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController, state = false)
0x017b5cf8 │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::ResetBackground(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b5cf8 │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::ResetBackground
0x017b7098 │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::SetSelect
0x017b3654 │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::SetSelect
0x017939f8 │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_Inventories(this = MaterialCell (Assets.Core.Game.Dialogs.Inventory.InventoryCellController))
0x017b4844 │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_Inventories(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b4844 │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_Inventories = Assets.Core.Models.InventoryModels.Inventories
0x017939f8 │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_Inventories = Assets.Core.Models.InventoryModels.Inventories
0x02524974 │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::get_Description(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell)
0x02524974 │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::get_Description = Assets.Core.Models.InventoryModels.InventoryCell.InventoryCellDescription
0x01793ab0 │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_InventoryIndex(this = MaterialCell (Assets.Core.Game.Dialogs.Inventory.InventoryCellController))
0x017b4834 │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_InventoryIndex(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b4834 │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_InventoryIndex = 0
0x01793ab0 │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_InventoryIndex = 0
0x01793b68 │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_InventoryCell(this = MaterialCell (Assets.Core.Game.Dialogs.Inventory.InventoryCellController))
0x017b483c │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_InventoryCellIndex(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b483c │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_InventoryCellIndex = 0
0x01793b68 │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_InventoryCell = 0
0x02526c40 │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell::CheckRemove(this = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell, other = null)
0x02526c40 │ └─Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell::CheckRemove = true
0x02525500 │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::OnStackAmountChanged(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack, oldamount = 10, newamount = 11)
0x02524fa4 │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::ClearEmptyStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell)
0x02524fa4 │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::ClearEmptyStack
0x02525500 │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::OnStackAmountChanged
0x02523e10 │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::OnStackChanged(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02523e10 │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::OnStackChanged
0x02525500 │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::OnStackAmountChanged(this = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack, oldamount = 1, newamount = 0)
0x02524fa4 │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::ClearEmptyStack(this = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell)
0x02523188 │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::Clear(this = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell)
0x025252b8 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::StackDetach(this = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell)
0x025252b8 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::StackDetach
0x025254b0 │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CallStackRemoved(this = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x017b5f08 │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::InventoryCellOnStackRemoved(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController, cell = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x017b5fb0 │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::UpdateStackController(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x02524998 │ │ │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::get_Entity(this = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell)
0x02524998 │ │ │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::get_Entity = null
0x01826d88 │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCell.StackTagsViewController::OnDispose(this = Assets.Core.Game.Dialogs.Inventory.InventoryCell.StackTagsViewController)
0x01868470 │ │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.Containers.InventoryCellContainer::ClearSlots(this = MaterialCell (Assets.Core.Game.Dialogs.Inventory.Containers.InventoryCellContainer))
0x01868470 │ │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.Containers.InventoryCellContainer::ClearSlots
0x01826d88 │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCell.StackTagsViewController::OnDispose
0x017b5cf8 │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::ResetBackground(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b5cf8 │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::ResetBackground
0x017b6d28 │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::UpdateCellDefault(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController, cellEnabled = false)
0x017b6d28 │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::UpdateCellDefault
0x017b5fb0 │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::UpdateStackController
0x017b68d0 │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::UpdateElementalController(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b6abc │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::BuildElementalCellController(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b6abc │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::BuildElementalCellController = Assets.Core.Game.Dialogs.Inventory.StackControllers.EmptyCellElementalModifierController
0x017b68d0 │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::UpdateElementalController
0x017b34c4 │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::OnProxyChanged(this = MaterialCell (Assets.Core.Game.Dialogs.Inventory.InventoryCellController))
0x017981b8 │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::SetActive(this = MaterialCell (Assets.Core.Game.Dialogs.Inventory.InventoryCellController), state = true)
0x017b72b0 │ │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::SetActive(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController, state = true)
0x017b5cf8 │ │ │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::ResetBackground(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b5cf8 │ │ │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::ResetBackground
0x01868614 │ │ │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.Containers.InventoryCellContainer::SetIconAlphaState(this = MaterialCell (Assets.Core.Game.Dialogs.Inventory.Containers.InventoryCellContainer), isTransparent = true)
0x01868614 │ │ │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.Containers.InventoryCellContainer::SetIconAlphaState
0x017b754c │ │ │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::SetRaycastActive(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController, state = true)
0x017b754c │ │ │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::SetRaycastActive
0x017b72b0 │ │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::SetActive
0x017981b8 │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::SetActive
0x017b34c4 │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::OnProxyChanged
0x017b5f08 │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::InventoryCellOnStackRemoved
0x025254b0 │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CallStackRemoved
0x02523188 │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::Clear
0x02524fa4 │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::ClearEmptyStack
0x02525500 │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::OnStackAmountChanged
0x01793ab0 │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_InventoryIndex(this = MaterialCell (Assets.Core.Game.Dialogs.Inventory.InventoryCellController))
0x017b4834 │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_InventoryIndex(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b4834 │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_InventoryIndex = 0
0x01793ab0 │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_InventoryIndex = 0
0x01793b68 │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_InventoryCell(this = MaterialCell (Assets.Core.Game.Dialogs.Inventory.InventoryCellController))
0x017b483c │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_InventoryCellIndex(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b483c │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_InventoryCellIndex = 0
0x01793b68 │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_InventoryCell = 0
0x017b1184 └─Assets.Core.Game.Dialogs.Inventory.CellProxyPointerEventsHandlerBase::HandleDoubleClick

[SM G988N::zombie.survival.craft.z ]->
[SM G988N::zombie.survival.craft.z ]->
[SM G988N::zombie.survival.craft.z ]->
[SM G988N::zombie.survival.craft.z ]->
[SM G988N::zombie.survival.craft.z ]->
[SM G988N::zombie.survival.craft.z ]->
[SM G988N::zombie.survival.craft.z ]->
[SM G988N::zombie.survival.craft.z ]->
[SM G988N::zombie.survival.craft.z ]->
[SM G988N::zombie.survival.craft.z ]->
[SM G988N::zombie.survival.craft.z ]->
[SM G988N::zombie.survival.craft.z ]->
[SM G988N::zombie.survival.craft.z ]-> il2cpp:
0x017b0efc ┌─Assets.Core.Game.Dialogs.Inventory.CellProxyPointerEventsHandlerBase::HandleCellSelection(this = Assets.Core.Game.Dialogs.Inventory.CellProxyPointerEventsHandlerMobile)
0x017b3654 │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::SetSelect(this = ResultCell (Assets.Core.Game.Dialogs.Inventory.InventoryCellController), state = true)
0x017b7098 │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::SetSelect(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController, state = true)
0x017b7098 │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::SetSelect
0x017b3654 │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::SetSelect
0x02526bdc │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::CheckRemove(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, other = null)
0x02526bdc │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::CheckRemove = true
0x017939f8 │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_Inventories(this = ResultCell (Assets.Core.Game.Dialogs.Inventory.InventoryCellController))
0x017b4844 │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_Inventories(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b4844 │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_Inventories = Assets.Core.Models.InventoryModels.Inventories
0x017939f8 │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_Inventories = Assets.Core.Models.InventoryModels.Inventories
0x01793ab0 │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_InventoryIndex(this = ResultCell (Assets.Core.Game.Dialogs.Inventory.InventoryCellController))
0x017b4834 │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_InventoryIndex(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b4834 │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_InventoryIndex = 0
0x01793ab0 │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_InventoryIndex = 0
0x01793b68 │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_InventoryCell(this = ResultCell (Assets.Core.Game.Dialogs.Inventory.InventoryCellController))
0x017b483c │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_InventoryCellIndex(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b483c │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_InventoryCellIndex = 0
0x01793b68 │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_InventoryCell = 0
0x02524974 │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::get_Description(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell)
0x02524974 │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::get_Description = Assets.Core.Models.InventoryModels.InventoryCell.InventoryCellDescription
0x017b0efc └─Assets.Core.Game.Dialogs.Inventory.CellProxyPointerEventsHandlerBase::HandleCellSelection

il2cpp:
0x017b1184 ┌─Assets.Core.Game.Dialogs.Inventory.CellProxyPointerEventsHandlerBase::HandleDoubleClick(this = Assets.Core.Game.Dialogs.Inventory.CellProxyPointerEventsHandlerMobile)
0x017b3654 │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::SetSelect(this = ResultCell (Assets.Core.Game.Dialogs.Inventory.InventoryCellController), state = false)
0x017b7098 │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::SetSelect(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController, state = false)
0x017b5cf8 │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::ResetBackground(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b5cf8 │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::ResetBackground
0x017b7098 │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::SetSelect
0x017b3654 │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::SetSelect
0x017939f8 │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_Inventories(this = ResultCell (Assets.Core.Game.Dialogs.Inventory.InventoryCellController))
0x017b4844 │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_Inventories(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b4844 │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_Inventories = Assets.Core.Models.InventoryModels.Inventories
0x017939f8 │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_Inventories = Assets.Core.Models.InventoryModels.Inventories
0x02524974 │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::get_Description(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell)
0x02524974 │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::get_Description = Assets.Core.Models.InventoryModels.InventoryCell.InventoryCellDescription
0x01793ab0 │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_InventoryIndex(this = ResultCell (Assets.Core.Game.Dialogs.Inventory.InventoryCellController))
0x017b4834 │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_InventoryIndex(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b4834 │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_InventoryIndex = 0
0x01793ab0 │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_InventoryIndex = 0
0x01793b68 │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_InventoryCell(this = ResultCell (Assets.Core.Game.Dialogs.Inventory.InventoryCellController))
0x017b483c │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_InventoryCellIndex(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b483c │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_InventoryCellIndex = 0
0x01793b68 │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_InventoryCell = 0
0x02526bdc │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::CheckRemove(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, other = null)
0x02526bdc │ └─Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell::CheckRemove = true
0x02522e44 │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::Add(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02524ddc │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::StackAttach(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell)
0x02524ddc │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::StackAttach
0x02525268 │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CallStackAdded(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x017b5f68 │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::InventoryCellOnStackAdded(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController, cell = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x017b5fb0 │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::UpdateStackController(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x018262e8 │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCell.StackTagsViewController::OnInit(this = Assets.Core.Game.Dialogs.Inventory.InventoryCell.StackTagsViewController)
0x018262e8 │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCell.StackTagsViewController::OnInit
0x02524998 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::get_Entity(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell)
0x02524998 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::get_Entity = Assets.Core.Models.Characters.CharacterModel
0x017b7144 │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::SetEnabled(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController, state = true)
0x0182693c │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCell.StackTagsViewController::SetEnabled(this = Assets.Core.Game.Dialogs.Inventory.InventoryCell.StackTagsViewController, state = true)
0x0182693c │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCell.StackTagsViewController::SetEnabled
0x017b6d28 │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::UpdateCellDefault(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController, cellEnabled = true)
0x017b6d28 │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::UpdateCellDefault
0x017b7144 │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::SetEnabled
0x017b5fb0 │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::UpdateStackController
0x017b68d0 │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::UpdateElementalController(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b6abc │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::BuildElementalCellController(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b6abc │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::BuildElementalCellController = Assets.Core.Game.Dialogs.Inventory.StackControllers.EmptyCellElementalModifierController
0x017b68d0 │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::UpdateElementalController
0x017b34c4 │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::OnProxyChanged(this = Cell (Assets.Core.Game.Dialogs.Inventory.InventoryCellController))
0x017981b8 │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::SetActive(this = Cell (Assets.Core.Game.Dialogs.Inventory.InventoryCellController), state = true)
0x017b72b0 │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::SetActive(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController, state = true)
0x017b5cf8 │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::ResetBackground(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b5cf8 │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::ResetBackground
0x01868614 │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.Containers.InventoryCellContainer::SetIconAlphaState(this = Cell (Assets.Core.Game.Dialogs.Inventory.Containers.InventoryCellContainer), isTransparent = false)
0x01868614 │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.Containers.InventoryCellContainer::SetIconAlphaState
0x017b754c │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::SetRaycastActive(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController, state = true)
0x017b754c │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::SetRaycastActive
0x017b72b0 │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::SetActive
0x017981b8 │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::SetActive
0x017b34c4 │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::OnProxyChanged
0x017b5f68 │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::InventoryCellOnStackAdded
0x02525268 │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CallStackAdded
0x02524fa4 │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::ClearEmptyStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell)
0x02524fa4 │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::ClearEmptyStack
0x02522e44 │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::Add
0x01793ab0 │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_InventoryIndex(this = ResultCell (Assets.Core.Game.Dialogs.Inventory.InventoryCellController))
0x017b4834 │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_InventoryIndex(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b4834 │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_InventoryIndex = 0
0x01793ab0 │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_InventoryIndex = 0
0x01793b68 │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_InventoryCell(this = ResultCell (Assets.Core.Game.Dialogs.Inventory.InventoryCellController))
0x017b483c │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_InventoryCellIndex(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b483c │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::get_InventoryCellIndex = 0
0x01793b68 │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::get_InventoryCell = 0
0x02523188 │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::Clear(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell)
0x025252b8 │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::StackDetach(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell)
0x025252b8 │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::StackDetach
0x025254b0 │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CallStackRemoved(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x017b5f08 │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::InventoryCellOnStackRemoved(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController, cell = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x017b5fb0 │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::UpdateStackController(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x02524998 │ │ │ │ │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::get_Entity(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell)
0x02524998 │ │ │ │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::get_Entity = null
0x01826d88 │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCell.StackTagsViewController::OnDispose(this = Assets.Core.Game.Dialogs.Inventory.InventoryCell.StackTagsViewController)
0x01868470 │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.Containers.InventoryCellContainer::ClearSlots(this = ResultCell (Assets.Core.Game.Dialogs.Inventory.Containers.InventoryCellContainer))
0x01868470 │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.Containers.InventoryCellContainer::ClearSlots
0x01826d88 │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCell.StackTagsViewController::OnDispose
0x017b5cf8 │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::ResetBackground(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b5cf8 │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::ResetBackground
0x017b6d28 │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::UpdateCellDefault(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController, cellEnabled = false)
0x017b6d28 │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::UpdateCellDefault
0x017b5fb0 │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::UpdateStackController
0x017b68d0 │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::UpdateElementalController(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b6abc │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::BuildElementalCellController(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b6abc │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::BuildElementalCellController = Assets.Core.Game.Dialogs.Inventory.StackControllers.EmptyCellElementalModifierController
0x017b68d0 │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::UpdateElementalController
0x017b34c4 │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::OnProxyChanged(this = ResultCell (Assets.Core.Game.Dialogs.Inventory.InventoryCellController))
0x017981b8 │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::SetActive(this = ResultCell (Assets.Core.Game.Dialogs.Inventory.InventoryCellController), state = true)
0x017b72b0 │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::SetActive(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController, state = true)
0x017b5cf8 │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::ResetBackground(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController)
0x017b5cf8 │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::ResetBackground
0x01868614 │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.Containers.InventoryCellContainer::SetIconAlphaState(this = ResultCell (Assets.Core.Game.Dialogs.Inventory.Containers.InventoryCellContainer), isTransparent = true)
0x01868614 │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.Containers.InventoryCellContainer::SetIconAlphaState
0x017b754c │ │ │ │ │ │ │ ┌─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::SetRaycastActive(this = Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController, state = true)
0x017b754c │ │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::SetRaycastActive
0x017b72b0 │ │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::SetActive
0x017981b8 │ │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::SetActive
0x017b34c4 │ │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellController::OnProxyChanged
0x017b5f08 │ │ │ └─Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::InventoryCellOnStackRemoved
0x025254b0 │ │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CallStackRemoved
0x02523188 │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::Clear
0x017b1184 └─Assets.Core.Game.Dialogs.Inventory.CellProxyPointerEventsHandlerBase::HandleDoubleClick

il2cpp:
0x02525a4c ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex(this = Assets.Core.Models.InventoryModels.InventoryCell.EquipInventoryCell, cellIndex = 0)
0x02525a4c └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex

il2cpp:
0x0252443c ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::add_Changed(this = Assets.Core.Models.InventoryModels.InventoryCell.EquipInventoryCell, value = Assets.Core.Models.InventoryModels.InventoryCell.InventoryCellHandler)
0x0252443c └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::add_Changed

il2cpp:
0x0252457c ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::add_StackAdded(this = Assets.Core.Models.InventoryModels.InventoryCell.EquipInventoryCell, value = Assets.Core.Models.InventoryModels.InventoryCell.InventoryCellAddStackHandler)
0x0252457c └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::add_StackAdded

il2cpp:
0x025246bc ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::add_StackRemoved(this = Assets.Core.Models.InventoryModels.InventoryCell.EquipInventoryCell, value = Assets.Core.Models.InventoryModels.InventoryCell.InventoryCellRemoveStackHandler)
0x025246bc └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::add_StackRemoved

il2cpp:
0x025247fc ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::add_StackAmountChanged(this = Assets.Core.Models.InventoryModels.InventoryCell.EquipInventoryCell, value = Assets.Core.Models.InventoryModels.InventoryCell.InventoryCellStackAmountChangedHandler)
0x025247fc └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::add_StackAmountChanged

il2cpp:
0x02524974 ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::get_Description(this = Assets.Core.Models.InventoryModels.InventoryCell.EquipInventoryCell)
0x02524974 └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::get_Description = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCellDescription

il2cpp:
0x02525a4c ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, cellIndex = 0)
0x02525a4c └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex

il2cpp:
0x0252443c ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::add_Changed(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, value = Assets.Core.Models.InventoryModels.InventoryCell.InventoryCellHandler)
0x0252443c └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::add_Changed

il2cpp:
0x0252457c ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::add_StackAdded(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, value = Assets.Core.Models.InventoryModels.InventoryCell.InventoryCellAddStackHandler)
0x0252457c └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::add_StackAdded

il2cpp:
0x025246bc ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::add_StackRemoved(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, value = Assets.Core.Models.InventoryModels.InventoryCell.InventoryCellRemoveStackHandler)
0x025246bc └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::add_StackRemoved

il2cpp:
0x025247fc ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::add_StackAmountChanged(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, value = Assets.Core.Models.InventoryModels.InventoryCell.InventoryCellStackAmountChangedHandler)
0x025247fc └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::add_StackAmountChanged

il2cpp:
0x02525a4c ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, cellIndex = 1)
0x02525a4c └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex

il2cpp:
0x02525a4c ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, cellIndex = 2)
0x02525a4c └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex

il2cpp:
0x02525a4c ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, cellIndex = 3)
0x02525a4c └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex

il2cpp:
0x02525a4c ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, cellIndex = 4)
0x02525a4c └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex

il2cpp:
0x02525a4c ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, cellIndex = 5)
0x02525a4c └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex

il2cpp:
0x02525a4c ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, cellIndex = 6)
0x02525a4c └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex

il2cpp:
0x02525a4c ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, cellIndex = 7)
0x02525a4c └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex

il2cpp:
0x02525a4c ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, cellIndex = 8)
0x02525a4c └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex

il2cpp:
0x02525a4c ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, cellIndex = 9)
0x02525a4c └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex

il2cpp:
0x02524974 ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::get_Description(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell)
0x02524974 └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::get_Description = Assets.Core.Models.InventoryModels.InventoryCell.InventoryCellDescription

il2cpp:
0x02525a4c ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex(this = Assets.Core.Models.InventoryModels.InventoryCell.EquipInventoryCell, cellIndex = 1)
0x02525a4c └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex

il2cpp:
0x02525a4c ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex(this = Assets.Core.Models.InventoryModels.InventoryCell.EquipInventoryCell, cellIndex = 2)
0x02525a4c └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex

il2cpp:
0x02525a4c ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex(this = Assets.Core.Models.InventoryModels.InventoryCell.EquipInventoryCell, cellIndex = 3)
0x02525a4c └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex

il2cpp:
0x02525a4c ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex(this = Assets.Core.Models.InventoryModels.InventoryCell.EquipInventoryCell, cellIndex = 4)
0x02525a4c └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex

il2cpp:
0x02525a4c ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex(this = Assets.Core.Models.InventoryModels.InventoryCell.EquipInventoryCell, cellIndex = 5)
0x02525a4c └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex

il2cpp:
0x02525a4c ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex(this = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell, cellIndex = 6)
0x02525a4c └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex

il2cpp:
0x0252443c ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::add_Changed(this = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell, value = Assets.Core.Models.InventoryModels.InventoryCell.InventoryCellHandler)
0x0252443c └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::add_Changed

il2cpp:
0x0252457c ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::add_StackAdded(this = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell, value = Assets.Core.Models.InventoryModels.InventoryCell.InventoryCellAddStackHandler)
0x0252457c └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::add_StackAdded

il2cpp:
0x025246bc ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::add_StackRemoved(this = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell, value = Assets.Core.Models.InventoryModels.InventoryCell.InventoryCellRemoveStackHandler)
0x025246bc └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::add_StackRemoved

il2cpp:
0x025247fc ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::add_StackAmountChanged(this = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell, value = Assets.Core.Models.InventoryModels.InventoryCell.InventoryCellStackAmountChangedHandler)
0x025247fc └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::add_StackAmountChanged

il2cpp:
0x02525a4c ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex(this = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell, cellIndex = 7)
0x02525a4c └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::SetIndex

il2cpp:
0x02524974 ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::get_Description(this = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCell)
0x02524974 └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::get_Description = Assets.Core.Models.InventoryModels.InventoryCell.TagInventoryCellDescription

il2cpp:
0x02522e44 ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::Add(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02524ddc │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::StackAttach(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell)
0x02524ddc │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::StackAttach
0x02525268 │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CallStackAdded(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02525268 │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CallStackAdded
0x02524fa4 │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::ClearEmptyStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell)
0x02524fa4 │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::ClearEmptyStack
0x02522e44 └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::Add

il2cpp:
0x02525500 ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::OnStackAmountChanged(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack, oldamount = 11, newamount = 15)
0x02524fa4 │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::ClearEmptyStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell)
0x02524fa4 │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::ClearEmptyStack
0x02525500 └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::OnStackAmountChanged

il2cpp:
0x02523e10 ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::OnStackChanged(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack)
0x02523e10 └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::OnStackChanged

il2cpp:
0x02525500 ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::OnStackAmountChanged(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.LimitedInventoryStack, oldamount = 15, newamount = 17)
0x02524fa4 │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::ClearEmptyStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell)
0x02524fa4 │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::ClearEmptyStack
0x02525500 └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::OnStackAmountChanged

il2cpp:
0x02522e44 ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::Add(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.SingleInventoryStack)
0x02524ddc │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::StackAttach(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell)
0x02524ddc │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::StackAttach
0x02525268 │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CallStackAdded(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.SingleInventoryStack)
0x02525268 │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CallStackAdded
0x02524fa4 │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::ClearEmptyStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell)
0x02524fa4 │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::ClearEmptyStack
0x02522e44 └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::Add

il2cpp:
0x02522e44 ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::Add(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.DurabilityInventoryStack)
0x02524ddc │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::StackAttach(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell)
0x02524ddc │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::StackAttach
0x02525268 │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CallStackAdded(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell, stack = Assets.Core.Models.InventoryModels.InventoryStack.DurabilityInventoryStack)
0x02525268 │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::CallStackAdded
0x02524fa4 │ ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::ClearEmptyStack(this = Assets.Core.Models.InventoryModels.InventoryCell.SimpleInventoryCell)
0x02524fa4 │ └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::ClearEmptyStack
0x02522e44 └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::Add

il2cpp:
0x0252461c ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::remove_StackAdded(this = Assets.Core.Models.InventoryModels.InventoryCell.EquipInventoryCell, value = Assets.Core.Models.InventoryModels.InventoryCell.InventoryCellAddStackHandler)
0x0252461c └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::remove_StackAdded

il2cpp:
0x0252475c ┌─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::remove_StackRemoved(this = Assets.Core.Models.InventoryModels.InventoryCell.EquipInventoryCell, value = Assets.Core.Models.InventoryModels.InventoryCell.InventoryCellRemoveStackHandler)
0x0252475c └─Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::remove_StackRemoved
