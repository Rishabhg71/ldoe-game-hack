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




[SM G988N::zombie.survival.craft.z ]-> il2cpp: 
0x0251d034+0x000 Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::Add
0x024e5ab4+0xc54 Assets.Core.Models.InventoryModels.Inventories::Add
0x017b4068+0x3c4 Assets.Core.Game.Dialogs.Inventory.InventoryHandler::OnDoubleClick
0x017a52a4+0x01c Assets.Core.Game.Dialogs.Inventory.InventoryButtonsHandler::OnDoubleClick
0x017a92ac+0x124 Assets.Core.Game.Dialogs.Inventory.CellProxyPointerEventsHandlerBase::HandleDoubleClick
0x017a9454+0x08c Assets.Core.Game.Dialogs.Inventory.CellProxyPointerEventsHandlerMobile::OnPointerClick
0x01a45eec+0x710 Assets.Core.Game.Battle.Touch.CustomInputModule::ProcessTouchPress
0x01a44efc+0x1a4 Assets.Core.Game.Battle.Touch.CustomInputModule::ProcessTouchEvents
0x01a44c98+0x04c Assets.Core.Game.Battle.Touch.CustomInputModule::Process

[SM G988N::zombie.survival.craft.z ]->
[SM G988N::zombie.survival.craft.z ]->
[SM G988N::zombie.survival.craft.z ]->
[SM G988N::zombie.survival.craft.z ]->
[SM G988N::zombie.survival.craft.z ]-> il2cpp: 
0x0251d034+0x000 Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::Add
0x024e5ab4+0xc54 Assets.Core.Models.InventoryModels.Inventories::Add
0x017a0de4+0x58c Assets.Core.Game.Dialogs.Inventory.InventoryButtonsHandler::TakeInventory
0x017a608c+0x0c4 Assets.Core.Game.Dialogs.Inventory.InventoryButtonsHandler::CallTakeAll
0x0179f564+0x0a8 Assets.Core.Game.Dialogs.Inventory.InventoryActionButtonController::get_Interactable
0x01b9a5dc+0x144 Assets.Core.Game.Battle.Gui.MainUI.Buttons.UiButtonControllerBase::OnPointerUp
0x01a45eec+0x4c4 Assets.Core.Game.Battle.Touch.CustomInputModule::ProcessTouchPress
0x01a44efc+0x1a4 Assets.Core.Game.Battle.Touch.CustomInputModule::ProcessTouchEvents
0x01a44c98+0x04c Assets.Core.Game.Battle.Touch.CustomInputModule::Process

il2cpp: 
0x0251d034+0x000 Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::Add
0x024e5ab4+0xc54 Assets.Core.Models.InventoryModels.Inventories::Add
0x017a0de4+0x58c Assets.Core.Game.Dialogs.Inventory.InventoryButtonsHandler::TakeInventory
0x017a0aa0+0x1ec Assets.Core.Game.Dialogs.Inventory.InventoryButtonsHandler::CallPutAll
0x0179f564+0x0a8 Assets.Core.Game.Dialogs.Inventory.InventoryActionButtonController::get_Interactable
0x01b9a5dc+0x144 Assets.Core.Game.Battle.Gui.MainUI.Buttons.UiButtonControllerBase::OnPointerUp
0x01a45eec+0x4c4 Assets.Core.Game.Battle.Touch.CustomInputModule::ProcessTouchPress
0x01a44efc+0x1a4 Assets.Core.Game.Battle.Touch.CustomInputModule::ProcessTouchEvents
0x01a44c98+0x04c Assets.Core.Game.Battle.Touch.CustomInputModule::Process

il2cpp: 
0x0251d034+0x000 Assets.Core.Models.InventoryModels.InventoryCell.InventoryCell::Add
0x024ea39c+0x308 Assets.Core.Models.InventoryModels.Inventories::DragItemTo
0x02db15f4+0x0e0 Firebase.Crashlytics.AndroidImpl::CallInternalMethod
0x017b4f7c+0x700 Assets.Core.Game.Dialogs.Inventory.InventoryHandler::DropItem
0x017a560c+0x01c Assets.Core.Game.Dialogs.Inventory.InventoryButtonsHandler::DropItem
0x017b4b38+0x41c Assets.Core.Game.Dialogs.Inventory.InventoryHandler::OnDrop
0x017afeac+0x0a8 Assets.Core.Game.Dialogs.Inventory.InventoryCellProxyController::OnDrop
0x01a45eec+0x788 Assets.Core.Game.Battle.Touch.CustomInputModule::ProcessTouchPress
0x01a44efc+0x1a4 Assets.Core.Game.Battle.Touch.CustomInputModule::ProcessTouchEvents
0x01a44c98+0x04c Assets.Core.Game.Battle.Touch.CustomInputModule::Process
