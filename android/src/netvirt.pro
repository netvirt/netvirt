TEMPLATE = app
TARGET = netvirt
QT += quick xml

SOURCES = main.cpp agent.cpp
HEADERS = agent.h

RESOURCES += \
    netvirt.qrc

OTHER_FILES = \
    $$files(*.qml) \
#     images \
    android/AndroidManifest.xml

# target.path = $$[QT_INSTALL_EXAMPLES]/sensors/accelbubble
# INSTALLS += target

# ios {
#     QMAKE_INFO_PLIST = Info.plist
# }

ANDROID_PACKAGE_SOURCE_DIR = $$PWD/android
