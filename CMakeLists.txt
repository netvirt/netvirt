cmake_minimum_required(VERSION 2.6)
project(dnds)

if(COMMAND cmake_policy)
	cmake_policy(SET CMP0003 NEW)
endif(COMMAND cmake_policy)

add_subdirectory(libdnds)
add_subdirectory(dnc)

if (NOT APPLE AND NOT WIN32)
	add_subdirectory(dsd)
	add_subdirectory(dnd)
endif()
