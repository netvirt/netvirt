set(CMAKE_SYSTEM_NAME "Windows")

# You might need to edit that section
#set(CROSS_COMPILER "i686-w64-mingw32")
#set(OPENSSL_ROOT_DIR "/opt/mingw32/mingw32")
#set(CMAKE_FIND_ROOT_PATH "/media/nib/Windows7_OS/Qt/4.8.4")

set(CMAKE_C_COMPILER "${CROSS_COMPILER}-gcc")
set(CMAKE_CXX_COMPILER "${CROSS_COMPILER}-g++")
set(CMAKE_RC_COMPILER "${CROSS_COMPILER}-windres")

