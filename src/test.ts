import "frida-il2cpp-bridge";
import * as fs from "fs";
import * as path from "path";


Il2Cpp.perform(() => {
    try {
        Il2Cpp.trace(true).domain().filterClasses((klass) => {
            if (klass.fullName.includes("Assets.Core.Models.Users.LocationObject.LocationObjectModel")) return true;
            return false;
        }).filterMethods((method) => {
            if (method.name === "Update") return false;
            if (method.name === "SetUId") return false;
            if (method.name === ".ctor") return false;
            if (method.name === "OnUpdate") return false;
            return true;
        }).and().attach();
    } catch (e) {
        console.log(e);
    }
});
