TEMPLATE = app
TARGET = netvirt
QT += quick xml svg

SOURCES = main.cpp
HEADERS = logging.h

SOURCES += agent.cpp config.cpp native_desktop.cpp service.cpp service_main.cpp
HEADERS += agent.h   config.h   native.h           service.h   service_main.h

RESOURCES += \
    netvirt.qrc

OTHER_FILES = \
    $$files(*.qml)
