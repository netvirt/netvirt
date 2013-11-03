cmake_minimum_required(VERSION 2.6)
project(dnds)

SET(CPACK_PACKAGE_VERSION "0.4")

if(COMMAND cmake_policy)
	cmake_policy(SET CMP0003 NEW)
endif(COMMAND cmake_policy)

if(APPLE)
	set(apple_package dnc.app) #DynVPN_Client.app)
	set(library_dest_dir ${apple_package}/Contents/MacOS)
	set(qtconf_dest_dir ${apple_package}/Contents/Resources)
else()
	set(library_dest_dir lib)
endif()

add_subdirectory(libdnds)

option (WITH_DNC "WITH_DNC" ON)

if (WITH_DNC)
	add_subdirectory(dnc)
endif()

option (WITH_DSD "WITH_DND" OFF)
option (WITH_DSD "WITH_DSD" OFF)

if (WITH_DSD)
	add_subdirectory(dsd)
endif()

if (WITH_DND)
	add_subdirectory(dnd)
endif()
