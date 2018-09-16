cmake_minimum_required(VERSION 2.6)
project(netvirt)

SET(CPACK_PACKAGE_VERSION "2.0.1b")

enable_testing()

# Using Hardening Options
# https://wiki.debian.org/Hardening
set(HARDENING OPTIONS_COMMON
    -W
    -Wall
    -fstack-protector-all
    --param ssp-buffer-size=4
    -Wformat
    -Wformat-security
    -Werror=format-security
    -D_FORTIFY_SOURCE=2
)

if (WIN32)
    set(compiler_options "${HARDENING_OPTIONS_COMMON} -fPIE -O1")
elseif(APPLE)
#    set(MACOS_10_6_FLAG "-stdlib=libstdc++")
#    set(CMAKE_OSX_SYSROOT "/SDKs/MacOSX10.6.sdk/")
#    set(compiler_options "${HARDENING_OPTIONS_COMMON} -fPIE ${MACOS_10_6_FLAG} -O1")
elseif(UNIX)
    set(HARDENING_OPTIONS_LINUX
        ${HARDENING_OPTIONS_COMMON}
    )
    set(compiler_options "${HARDENING_OPTIONS_LINUX} -O1")
endif()

if(COMMAND cmake_policy)
	cmake_policy(SET CMP0003 NEW)
endif(COMMAND cmake_policy)

if(APPLE)
	set(apple_package netvirt-agent.app)
	set(library_dest_dir ${apple_package}/Contents/MacOS)
	set(qtconf_dest_dir ${apple_package}/Contents/Resources)
else()
	set(library_dest_dir lib)
endif()

add_subdirectory(libnv)

option (WITH_GUI "WITH_GUI" OFF)
option (WITH_NVAGENT "WITH_NVAGENT" ON)

if (WITH_NVAGENT)
	add_subdirectory(nvagent)
endif()

option (WITH_NVSWITCH "WITH_NVSWITCH" OFF)
option (WITH_NVCTRLER "WITH_NVCTRLER" OFF)

if (WITH_NVCTRLER)
	add_subdirectory(nvctrler)
endif()

if (WITH_NVSWITCH)
	add_subdirectory(nvswitch)
endif()
