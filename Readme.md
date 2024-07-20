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
