set(CMAKE_C_FLAGS "-g -Wall")
add_executable(dnd
	context.c
	dnd.c
	dsc.c
	inet.c
	linkst.c
	main.c
	request.c
	session.c
)

include_directories("${CMAKE_SOURCE_DIR}/libdnds/src/")
include_directories("${CMAKE_SOURCE_DIR}/libdnds/src/protocol/")
target_link_libraries(dnd
	dnds
	config
	ssl
	crypto
	pthread
)

install(TARGETS dnd
	DESTINATION bin)
