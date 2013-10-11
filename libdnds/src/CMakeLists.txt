set(CMAKE_C_FLAGS "-g -Wall")
set(CMAKE_CXX_FLAGS "-g -Wall")

add_subdirectory(protocol)
include_directories(protocol)

set(DNDS_SRCS
	bitv.c
	dnds.c
	logger.c
	crypto.c
	mbuf.c
	netbus.c
	udt.cpp
)

add_library(dnds ${DNDS_SRCS})

include_directories(${CMAKE_SOURCE_DIR}/udt4/src/)

if(WIN32)

	find_package(OpenSSL REQUIRED)
	include_directories(${OPENSSL_INCLUDE_DIR})

	set(UDT_LIBRARIES ${CMAKE_SOURCE_DIR}/udt4/src/libudt.dll)
	target_link_libraries(dnds
		ws2_32
	)
else()
	set(UDT_LIBRARIES ${CMAKE_SOURCE_DIR}/udt4/src/libudt.a)
	target_link_libraries(dnds
#		-Wl,-Bstatic
#		dl
#		crypto
#		ssl
#		-Wl,-Bdynamic
	)

#	install(TARGETS dnds
#		LIBRARY DESTINATION ${library_dest_dir} COMPONENT Runtime)
endif()

target_link_libraries(dnds
	${UDT_LIBRARIES}
#	${OPENSSL_LIBRARIES}
	dnds_protocol
#	pthread
)


