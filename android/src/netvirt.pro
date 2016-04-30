TEMPLATE = app
TARGET = netvirt
QT += quick xml androidextras

ANDROID_PACKAGE_SOURCE_DIR = $$PWD/android

SOURCES = main.cpp agent.cpp service.cpp
HEADERS = agent.h service.h

RESOURCES += \
    netvirt.qrc

OTHER_FILES = \
    $$files(*.qml) \
    android/AndroidManifest.xml\
    android/src/com/netvirt/netvirt/NetvirtAgent.java \
    android/src/com/netvirt/netvirt/ToyVpnService.java \
    android/src/com/netvirt/netvirt/ToyVpnServiceQt.java
