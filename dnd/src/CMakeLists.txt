set(CMAKE_C_FLAGS "-g -Wall")
add_executable(dnd
	context.c
	dnd.c
	dsc.c
	ftable.c
	hash.c
	inet.c
	jsw_hlib.c
	linkst.c
	main.c
	request.c
	session.c
)
link_directories("${CMAKE_SOURCE_DIR}/libconfig-linux/lib/.libs")
include_directories("${CMAKE_SOURCE_DIR}/libconfig-linux/lib/")

include_directories("${CMAKE_SOURCE_DIR}/libdnds/src/")
include_directories("${CMAKE_SOURCE_DIR}/libdnds/src/protocol/")
target_link_libraries(dnd
	${CMAKE_SOURCE_DIR}/libconfig-linux/lib/.libs/libconfig.a
	dnds
	ssl
	crypto
	pthread
)

install(TARGETS dnd
	DESTINATION bin)
