add_subdirectory(protocol)
include_directories(protocol)

set(DNDS_SRCS
	bitpool.c
	dnds.c
	event.c
	inet.c
	journal.c
	krypt.c
	mbuf.c
	net.c
	netbus.c
	options.c
	udtbus.cpp
	utils.c
	xsched.c
)

if (CMAKE_SYSTEM_NAME MATCHES "Linux")
	set (DNDS_SRCS ${DNDS_SRCS} ion_epoll.c tun_ifreq.c)
endif (CMAKE_SYSTEM_NAME MATCHES "Linux")

if (CMAKE_SYSTEM_NAME MATCHES "OpenBSD")
	set (DNDS_SRCS ${DNDS_SRCS} ion_kqueue.c tun_tuninfo.c)
endif (CMAKE_SYSTEM_NAME MATCHES "OpenBSD")

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
