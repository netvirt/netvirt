set(CMAKE_C_FLAGS "-g -Wall")
add_executable(dnc
	main.c
	dnc.c
	session.c
)

include_directories("${CMAKE_SOURCE_DIR}/libdnds/src/protocol/")
include_directories("${CMAKE_SOURCE_DIR}/tapcfg-1.0.0/src/include/")
set(TAPCFG_LIBRARIES ${CMAKE_SOURCE_DIR}/tapcfg-1.0.0/build/libtapcfg.a)
target_link_libraries(dnc
	${TAPCFG_LIBRARIES}
	dnds
	crypto
	config
)

install(TARGETS dnc
	DESTINATION bin)
