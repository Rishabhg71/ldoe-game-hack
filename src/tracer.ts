import "frida-il2cpp-bridge";

Il2Cpp.perform(() => {
    Il2Cpp.trace(true).domain().filterClasses((klass) => {
        return klass.fullName.includes("Assets.Core.Models.InventoryModels.Inventories");
    }).and().attach();
})
// function trace() {
// }
// rpc.exports = {
//     trace
// }
