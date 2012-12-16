cmake_minimum_required(VERSION 2.6)

if(COMMAND cmake_policy)
	cmake_policy(SET CMP0003 NEW)
endif(COMMAND cmake_policy)

include_directories("../libdnds/src/")
include_directories("../libdnds/protocol/")

add_subdirectory(src)

install(FILES dsd.conf
        DESTINATION etc/dnds/)
