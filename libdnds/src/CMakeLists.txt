add_subdirectory(protocol)
include_directories(protocol)

set(DNDS_SRCS
	bitv.c
	dnds.c
	inet.c
	logger.c
	crypto.c
	mbuf.c
	netbus.c
	udt.cpp
	utils.c
)

add_library(dnds SHARED ${DNDS_SRCS})

find_package(OpenSSL REQUIRED)

include_directories(${CMAKE_SOURCE_DIR}/udt4/src/)
set(UDT_LIBRARIES ${CMAKE_SOURCE_DIR}/udt4/src/libudt.a)

target_link_libraries(dnds
	${UDT_LIBRARIES}
	${OPENSSL_LIBRARIES}
	dnds_protocol
	dl
	pthread
)

install(TARGETS dnds
	LIBRARY DESTINATION lib)
