set(CMAKE_C_FLAGS "-g -W -Wall ${compiler_options}")
set(CMAKE_CXX_FLAGS "-g -W -Wall ${compiler_options}")

add_subdirectory(tests)
add_subdirectory(protocol)
include_directories(protocol)

set(NVCORE_SRCS
	bitv.c
	cert.c
	dnds.c
	ftable.c
	hash.c
	jsw_hlib.c
	logger.c
	crypto.c
	mbuf.c
	netbus.c
	udt.cpp
)

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
set(NVCORE_SRCS ${NVCORE_SRCS} tcp.c)
endif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")

add_library(nvcore ${NVCORE_SRCS})

include_directories(${CMAKE_SOURCE_DIR}/udt4/src/)

if(WIN32)

	find_package(OpenSSL REQUIRED)
	include_directories(${OPENSSL_INCLUDE_DIR})

	set(UDT_LIBRARIES ${CMAKE_SOURCE_DIR}/udt4/src/libudt.dll)
	target_link_libraries(nvcore
		ws2_32
	)
else()
	set(UDT_LIBRARIES ${CMAKE_SOURCE_DIR}/udt4/src/libudt.a)
	target_link_libraries(nvcore
#		-Wl,-Bstatic
#		dl
#		crypto
#		ssl
#		-Wl,-Bdynamic
	)

#	install(TARGETS nvcore
#		LIBRARY DESTINATION ${library_dest_dir} COMPONENT Runtime)
endif()

target_link_libraries(nvcore
	${UDT_LIBRARIES}
#	${OPENSSL_LIBRARIES}
	dnds_protocol
#	pthread
)
