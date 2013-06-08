set(CMAKE_C_FLAGS "-g -Wall")
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
	utils.c
)

add_library(dnds SHARED ${DNDS_SRCS})

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

include_directories(${CMAKE_SOURCE_DIR}/udt4/src/)
set(UDT_LIBRARIES ${CMAKE_SOURCE_DIR}/udt4/src/libudt.a)

target_link_libraries(dnds
	${UDT_LIBRARIES}
	${OPENSSL_LIBRARIES}
	dnds_protocol
	pthread
	crypto
	ssl
)

if(WIN32)
	target_link_libraries(dnds
		wsock32
		ws2_32
	)
else()
	target_link_libraries(dnds
		dl
	)
endif()

#install(TARGETS dnds
#	LIBRARY DESTINATION lib)
