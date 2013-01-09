cmake_minimum_required(VERSION 2.6)

include_directories("../libdnds/src/")
include_directories("../libdnds/protocol/")

add_subdirectory(src)

install(FILES dnc.conf
	DESTINATION /etc/dnds/)
