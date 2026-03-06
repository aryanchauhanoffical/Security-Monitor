# Android Logcat without Root

[![Get it on Google Play](http://www.tananaev.com/badges/google-play.svg)](https://play.google.com/store/apps/details?id=com.tananaev.logcat) [![Get it on F-Droid](http://www.tananaev.com/badges/f-droid.svg)](https://f-droid.org/repository/browse/?fdid=com.tananaev.logcat)

Read Android logs without root access. The app uses remote debugging to connect to phone local ADB daemon. Configuring remote debugging on a phone can be challenging and requires some technical expertise. It has to be done once and after each device reboot.

Enable USB debugging first on your device. Navigate to Settings > About Phone and tap Build number seven times. Go back, access the Developer options menu and check USB debugging option.

Next step is to enable remote debugging. You need to have Android SDK installed on your computer. Connect your phone via USB cable and run following adb command:

```
adb tcpip 5555
```

Disconnect USB cable before trying to use the app. Some phones have problems handling network ADB connection when they are connected via USB as well.

Sometimes establishing connection to ADB hangs and requires killing and restarting the app. It seems to be a problem with ADB daemon itself and not the app issue.

## Contacts

Author - Anton Tananaev ([anton.tananaev@gmail.com](mailto:anton.tananaev@gmail.com))

## License

    Apache License, Version 2.0

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

How to use it on your phone:
Transfer this APK file to your Android phone.

Install it (you may need to allow "Install from Unknown Sources").

Crucial Step: For the app to be able to read system logs without root, you must connect your phone to your PC and run this ADB command once to enable wireless debugging on port 5555: adb tcpip 5555

Open the "Security Monitor" app on your phone. It will start the background service and you should see the dashboard reporting the security status!

Let me know if you need any help getting it running or if you want to test further modifications!

To run the ADB command for the app to work on your phone, you need to run it from your computer's terminal (Command Prompt or PowerShell) while your phone is plugged in via USB.

Here are the step-by-step instructions to do this:

1. Enable Developer Options & USB Debugging on your Phone
Go to your phone's Settings > About phone.
Tap on "Build number" 7 times rapidly until it says "You are now a developer!".
Go back to the main Settings menu and find Developer options (sometimes under "System").
Scroll down and turn on USB debugging.
2. Connect Your Phone to Your PC
Plug your Android phone into your computer using a USB cable.
Look at your phone's screen. A prompt will appear asking "Allow USB debugging?".
Check "Always allow from this computer" and tap OK.
3. Run the Command on Your PC
Open PowerShell on your Windows computer.
Since you have the Android SDK installed, you can use the exact same ADB path we used earlier. Paste this exact command into PowerShell and hit Enter:
powershell
& "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe" tcpip 5555

If successful, it should say restarting in TCP mode port: 5555.
4. You're Done!
You can now unplug your phone from the USB cable. Open the Security Monitor app you installed. It will use this open port to connect to the system logs internally without needing root access, and the dashboard will start monitoring your device for threats!

(Note: If you restart your phone, the port closes for security reasons, so you would just need to plug it into your computer and run that one command again)
