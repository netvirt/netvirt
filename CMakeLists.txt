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
add_subdirectory(dnc)

#if (NOT APPLE AND NOT WIN32)
#	add_subdirectory(dsd)
#	add_subdirectory(dnd)
#endif()
