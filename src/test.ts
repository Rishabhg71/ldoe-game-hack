import "frida-il2cpp-bridge";

console.log("Frida Loaded Successfully");

const checkIl2cppLoaded = () => {
    if (Process.enumerateModules().some(module => module.name === "libil2cpp.so")) {
        console.log("libil2cpp.so loaded, performing Il2Cpp operations...");

        Il2Cpp.perform(() => {
            const AssemblyCSharp = Il2Cpp.domain.assembly("Assembly-CSharp").image;
            console.log("Loaded Assembly-CSharp:", AssemblyCSharp);
            const GlobalMap = AssemblyCSharp.class("Assets.Core.Game");
            console.log("Loaded GlobalMap:", GlobalMap);

            const Client = Il2Cpp.domain.assembly("Client").image;
            console.log("Loaded Client:", Client);
            const Inventory = Client.class("Assets.Core.Game.Dialogs.Inventory");
            console.log("Loaded Inventory:", Inventory);

            Il2Cpp.trace(true).classes(GlobalMap, Inventory).and().attach();
            console.log("Tracing started");
        });
    } else {
        console.log("libil2cpp.so not loaded yet, retrying...");
        setTimeout(checkIl2cppLoaded, 5000); // Retry after 5 seconds
    }
};

setTimeout(checkIl2cppLoaded, 5000); // Start checking after 5 seconds
