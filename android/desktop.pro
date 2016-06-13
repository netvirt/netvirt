TEMPLATE = app
TARGET = netvirt
QT += quick xml svg

SOURCES = src/main.cpp
HEADERS = src/logging.h

SOURCES += src/agent.cpp src/config.cpp src/native_desktop.cpp src/service.cpp src/service_main.cpp
HEADERS += src/agent.h   src/config.h   src/native.h           src/service.h   src/service_main.h

RESOURCES += \
    src/netvirt.qrc

OTHER_FILES = \
    $$files(src/*.qml)
