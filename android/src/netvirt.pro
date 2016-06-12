TEMPLATE = app
TARGET = netvirt
QT += quick xml androidextras svg

ANDROID_PACKAGE_SOURCE_DIR = $$PWD/android

SOURCES = main.cpp
HEADERS = logging.h

SOURCES += agent.cpp config.cpp native_android.cpp service.cpp service_main.cpp
HEADERS += agent.h   config.h   native.h           service.h  service_main.h

RESOURCES += \
    netvirt.qrc

OTHER_FILES = \
    $$files(*.qml) \
    android/AndroidManifest.xml\
    android/src/com/netvirt/netvirt/NetvirtAgent.java \
    android/src/com/netvirt/netvirt/ToyVpnService.java \
    android/src/com/netvirt/netvirt/ToyVpnServiceQt.java
