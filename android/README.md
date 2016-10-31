Netvirt Agent Android
=====================

Prerequisites
-------------

For compiling:

* Docker
* `docker pull rabits/qt:5.4-android`

For packaging/signing:

* Android SDK with binaries from /tools and /platform-tools in your `$PATH` (on Debian: `apt-get install openjdk-7-jre-headless android-tools-adb openjdk-7-jdk`)
* `make keygen  # generates a keystore for signing the APK`

How to test
-----------

```
make  # compiles for Android
make apk  # creates the APK Android package
make sign  # signs the APK
make install  # installs the APK on an emulator/device via adb
```

How to enable Android device debugging
--------------------------------------

On your Android device:
- Settings > Security > Unknown sources = true
- Settings > About {tablet,phone}: Tap 8 times on "Build number"
- Settings > Developer options > USB debugging = true

On your machine (after plugging and turning on the device):
- `lsusb | grep -i google  # note the Bus XXX Device YYY`
- `lsusb -vs XXX:YYY | grep idVendor  # note the idVendor 0xZZZZ`
- `echo 'SUBSYSTEM=="usb", ATTR{idVendor}=="ZZZZ", MODE="0666", GROUP="androidsdk"' > /etc/udev/rules.d/51-android.rules`
- `gpasswd $USER androidsdk  # then logout/login`

Then unplug and replug the device.


How to get logs from Android
----------------------------

Run this command to print logs:

`adb logcat`


The code needed to generate logs looks like:

Java:
```
import android.util.Log;

Log.i("ToyVpnService", "message");
```

C++:
```
#include <android/log.h>

__android_log_write(ANDROID_LOG_INFO, "ToyVpnService", "message");

```

Integration tests
-----------------

Prerequisites:
- Docker
- run:
```
cd integration_tests
pip install -r requirements.txt
```

To run the tests:

```
make test-setup  # recompile client code changes
cd integration_tests
nosetests -x suite
```

Nosetests is a Python executable that looks for any Python function `test_*` or any method `Test*.test_*`, and run them.

Tests use a slightly modified version of the client: it uses the "native" implementation (meaning: no Java) with a different "main_test.c" entry point.
