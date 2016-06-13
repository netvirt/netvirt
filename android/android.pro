TEMPLATE = app
TARGET = netvirt
QT += quick xml androidextras svg

ANDROID_PACKAGE_SOURCE_DIR = $$PWD/src/android

SOURCES = src/main.cpp
HEADERS = src/logging.h

SOURCES += src/agent.cpp src/config.cpp src/native_android.cpp src/service.cpp src/service_main.cpp
HEADERS += src/agent.h   src/config.h   src/native.h           src/service.h   src/service_main.h

RESOURCES += \
    src/netvirt.qrc

OTHER_FILES = \
    $$files(src/*.qml) \
    src/android/AndroidManifest.xml\
    src/android/src/com/netvirt/netvirt/NetvirtAgent.java \
    src/android/src/com/netvirt/netvirt/ToyVpnService.java \
    src/android/src/com/netvirt/netvirt/ToyVpnServiceQt.java
