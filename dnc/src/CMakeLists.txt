set(CMAKE_C_FLAGS "-g -Wall")
add_executable(dnc
	config.c
	main.c
	dnc.c
	session.c
)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

include_directories("${CMAKE_SOURCE_DIR}/libdnds/src/protocol/")
include_directories("${CMAKE_SOURCE_DIR}/tapcfg-1.0.0/src/include/")
include_directories("${CMAKE_SOURCE_DIR}/libconfig-1.4.9/lib")

if(WIN32)

	set(TAPCFG_LIBRARIES ${CMAKE_SOURCE_DIR}/tapcfg-1.0.0/build/tapcfg.dll)
	set(LIBCONFIG_LIBRARIES ${CMAKE_SOURCE_DIR}/libconfig-1.4.9/lib/.libs/libconfig-9.dll)

	target_link_libraries(dnc
		${TAPCFG_LIBRARIES}
		${LIBCONFIG_LIBRARIES}
		dnds
	)

else()
	set(TAPCFG_LIBRARIES ${CMAKE_SOURCE_DIR}/tapcfg-1.0.0/build/libtapcfg.a)

	target_link_libraries(dnc
		${TAPCFG_LIBRARIES}
		${LIBCONFIG_LIBRARIES}
		dnds
		config
	)
endif()

target_link_libraries(dnc
	${TAPCFG_LIBRARIES}
	${LIBCONFIG_LIBRARIES}
	dnds
)

install(TARGETS dnc
	DESTINATION bin)
