import keyboard
import subprocess

# Global variable to keep track of the Frida process
frida_process = None

TARGET_PROCESS = "zombie.survival.craft.z"

def toggle_frida_script():
	global frida_process
	# If there's a running Frida process, terminate it
	if frida_process:
		frida_process.terminate()
		frida_process = None
		print("Frida script terminated.")
	else:
		# Start a new Frida process
		command = f"frida -U -f {TARGET_PROCESS} -l your_frida_script.js --no-pause"
		frida_process = subprocess.Popen(command, shell=True)
		print("Frida script started.")

# Listen for the F12 hotkey
keyboard.add_hotkey('F12', toggle_frida_script)

# Block the script so it doesn't exit immediately
keyboard.wait('esc')