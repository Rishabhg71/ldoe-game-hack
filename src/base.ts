
type resolve = (value: any) => void;
type callback = (resolve: resolve) => Promise<void>;

export default class BaseWrapper {
    wrapper(callback: callback) {
        return new Promise((resolve, reject) => {
            setImmediate(async () => {
                try {
                    await callback(resolve);

                } catch (error) {
                    console.error("Error", error);
                    resolve(true);
                }
            });
        });
    }
}