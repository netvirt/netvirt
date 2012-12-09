cmake_minimum_required(VERSION 2.6)
project(libdnds)

if(COMMAND cmake_policy)
	cmake_policy(SET CMP0003 NEW)
endif(COMMAND cmake_policy)

add_subdirectory("${CMAKE_SOURCE_DIR}/src/")


