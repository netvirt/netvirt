Netvirt Agent Android
=====================

Prerequisites
-------------

For compiling:

* Docker
* `docker pull rabits/qt:5.4-android`

For packaging/signing:

* Android SDK with binaries from /tools and /platform-tools in your `$PATH`
* `make keygen  # generates a keystore for signing the APK`

How to test
-----------

```
make  # compiles for Android
make apk  # creates the APK Android package
make sign  # signs the APK
make install  # installs the APK on an emulator/device via adb
```
