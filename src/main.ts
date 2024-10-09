import "frida-il2cpp-bridge";

async function main() {
    return new Promise<void>((resolve, reject) => {
        Il2Cpp.perform(async () => {
            console.log("Il2Cpp loaded");
            resolve();
        });
    });
}

rpc.exports = {
    main: main,
}
